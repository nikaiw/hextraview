package burp;

import java.util.ArrayDeque;
import java.util.Arrays;
import java.util.Deque;

/**
 * Parser for WebSocket payloads that identifies structural regions
 * for syntax-aware coloring. Supports:
 * <ul>
 *   <li>JSON structure (keys, strings, numbers, literals, structural chars)</li>
 *   <li>Protobuf wire format (tags, varints, fixed values, length-delimited fields)</li>
 *   <li>Generic text vs binary detection as fallback</li>
 * </ul>
 */
public class WebSocketPayloadParser {

    public enum Region {
        KEY,        // JSON property keys
        STRING,     // JSON string values / protobuf strings / text regions
        NUMBER,     // JSON numbers / protobuf varint & fixed values
        STRUCTURE,  // JSON structural chars / protobuf field tags & length prefixes
        LITERAL,    // JSON true/false/null
        BINARY,     // Raw binary data regions
        DEFAULT     // Whitespace / unclassified
    }

    public enum PayloadType {
        JSON, PROTOBUF, TEXT_BINARY, UNKNOWN
    }

    private Region[] regionMap;
    private PayloadType detectedType = PayloadType.UNKNOWN;

    public void parse(byte[] payload) {
        if (payload == null || payload.length == 0) {
            regionMap = new Region[0];
            detectedType = PayloadType.UNKNOWN;
            return;
        }

        regionMap = new Region[payload.length];
        Arrays.fill(regionMap, Region.DEFAULT);
        jsonStartOffset = 0;

        if (isLikelyJson(payload)) {
            parseJson(payload);
            detectedType = PayloadType.JSON;
        } else if (isLikelyProtobuf(payload)) {
            parseProtobuf(payload);
            detectedType = PayloadType.PROTOBUF;
        } else {
            parseTextBinary(payload);
            detectedType = PayloadType.TEXT_BINARY;
        }
    }

    public Region getRegionAt(long position) {
        if (regionMap == null || position < 0 || position >= regionMap.length) {
            return Region.DEFAULT;
        }
        return regionMap[(int) position];
    }

    public PayloadType getDetectedType() {
        return detectedType;
    }

    // ── JSON detection and parsing ─────────────────────────────────────

    // Offset where JSON actually starts (after any protocol prefix digits)
    private int jsonStartOffset = 0;

    /**
     * Detects JSON payloads, including those prefixed by Engine.IO / Socket.IO
     * packet-type digits (e.g. {@code 0&#123;...&#125;}, {@code 42[...]}).
     */
    private boolean isLikelyJson(byte[] data) {
        int i = 0;
        // Skip leading whitespace
        while (i < data.length) {
            char c = (char) (data[i] & 0xFF);
            if (c != ' ' && c != '\t' && c != '\r' && c != '\n') break;
            i++;
        }
        // Skip optional Engine.IO/Socket.IO digit prefix (e.g. "0", "42", "451")
        int digitStart = i;
        while (i < data.length) {
            char c = (char) (data[i] & 0xFF);
            if (c < '0' || c > '9') break;
            i++;
        }
        // After optional digits, the next char must be { or [
        if (i < data.length) {
            char c = (char) (data[i] & 0xFF);
            if (c == '{' || c == '[') {
                jsonStartOffset = i;
                return true;
            }
        }
        return false;
    }

    private enum JsonState { OUTSIDE, IN_KEY, IN_STRING, IN_NUMBER, IN_LITERAL }
    private enum ContainerType { OBJECT, ARRAY }

    private void parseJson(byte[] data) {
        // Mark any Engine.IO/Socket.IO prefix digits as STRUCTURE
        for (int p = 0; p < jsonStartOffset; p++) {
            char c = (char) (data[p] & 0xFF);
            if (c >= '0' && c <= '9') {
                regionMap[p] = Region.STRUCTURE;
            }
            // whitespace stays DEFAULT
        }

        JsonState state = JsonState.OUTSIDE;
        Deque<ContainerType> stack = new ArrayDeque<>();
        boolean expectingKey = false;
        boolean escaped = false;
        int literalRemaining = 0;

        for (int i = jsonStartOffset; i < data.length; i++) {
            char c = (char) (data[i] & 0xFF);

            switch (state) {
                case OUTSIDE:
                    if (c == '{') {
                        regionMap[i] = Region.STRUCTURE;
                        stack.push(ContainerType.OBJECT);
                        expectingKey = true;
                    } else if (c == '}') {
                        regionMap[i] = Region.STRUCTURE;
                        if (!stack.isEmpty()) stack.pop();
                    } else if (c == '[') {
                        regionMap[i] = Region.STRUCTURE;
                        stack.push(ContainerType.ARRAY);
                        expectingKey = false;
                    } else if (c == ']') {
                        regionMap[i] = Region.STRUCTURE;
                        if (!stack.isEmpty()) stack.pop();
                    } else if (c == ':') {
                        regionMap[i] = Region.STRUCTURE;
                        expectingKey = false;
                    } else if (c == ',') {
                        regionMap[i] = Region.STRUCTURE;
                        if (!stack.isEmpty() && stack.peek() == ContainerType.OBJECT) {
                            expectingKey = true;
                        }
                    } else if (c == '"') {
                        if (expectingKey) {
                            state = JsonState.IN_KEY;
                            regionMap[i] = Region.KEY;
                        } else {
                            state = JsonState.IN_STRING;
                            regionMap[i] = Region.STRING;
                        }
                        escaped = false;
                    } else if (c == '-' || (c >= '0' && c <= '9')) {
                        state = JsonState.IN_NUMBER;
                        regionMap[i] = Region.NUMBER;
                    } else if (c == 't' || c == 'f' || c == 'n') {
                        state = JsonState.IN_LITERAL;
                        regionMap[i] = Region.LITERAL;
                        literalRemaining = (c == 'f') ? 4 : 3; // false=4, true/null=3
                    }
                    // whitespace stays DEFAULT
                    break;

                case IN_KEY:
                    regionMap[i] = Region.KEY;
                    if (escaped) {
                        escaped = false;
                    } else if (c == '\\') {
                        escaped = true;
                    } else if (c == '"') {
                        state = JsonState.OUTSIDE;
                        expectingKey = false;
                    }
                    break;

                case IN_STRING:
                    regionMap[i] = Region.STRING;
                    if (escaped) {
                        escaped = false;
                    } else if (c == '\\') {
                        escaped = true;
                    } else if (c == '"') {
                        state = JsonState.OUTSIDE;
                    }
                    break;

                case IN_NUMBER:
                    if ((c >= '0' && c <= '9') || c == '.' || c == 'e' || c == 'E'
                            || c == '+' || c == '-') {
                        regionMap[i] = Region.NUMBER;
                    } else {
                        state = JsonState.OUTSIDE;
                        i--; // re-process this byte in OUTSIDE state
                    }
                    break;

                case IN_LITERAL:
                    regionMap[i] = Region.LITERAL;
                    literalRemaining--;
                    if (literalRemaining <= 0) {
                        state = JsonState.OUTSIDE;
                    }
                    break;
            }
        }
    }

    // ── Protobuf detection and parsing ─────────────────────────────────

    private boolean isLikelyProtobuf(byte[] data) {
        if (data.length < 2) return false;

        // If first 64 bytes are all printable ASCII, it's not protobuf
        boolean allPrintable = true;
        for (int i = 0; i < Math.min(data.length, 64); i++) {
            int b = data[i] & 0xFF;
            if (b < 32 || b > 126) {
                if (b != '\r' && b != '\n' && b != '\t') {
                    allPrintable = false;
                    break;
                }
            }
        }
        if (allPrintable) return false;

        // Trial-decode a few protobuf fields
        int pos = 0;
        int fieldsDecoded = 0;
        while (pos < data.length && fieldsDecoded < 10) {
            long[] tagResult = decodeVarint(data, pos, data.length);
            if (tagResult == null) break;
            long tag = tagResult[0];
            int tagEnd = (int) tagResult[1];

            int fieldNumber = (int) (tag >>> 3);
            int wireType = (int) (tag & 0x7);
            if (fieldNumber < 1 || fieldNumber > 536870911) break;
            if (wireType != 0 && wireType != 1 && wireType != 2 && wireType != 5) break;

            pos = tagEnd;
            switch (wireType) {
                case 0:
                    long[] v = decodeVarint(data, pos, data.length);
                    if (v == null) return false;
                    pos = (int) v[1];
                    break;
                case 1:
                    pos += 8;
                    if (pos > data.length) return false;
                    break;
                case 2:
                    long[] l = decodeVarint(data, pos, data.length);
                    if (l == null) return false;
                    long len = l[0];
                    pos = (int) l[1];
                    if (len < 0 || pos + len > data.length) return false;
                    pos += (int) len;
                    break;
                case 5:
                    pos += 4;
                    if (pos > data.length) return false;
                    break;
                default:
                    return false;
            }
            fieldsDecoded++;
        }

        return fieldsDecoded >= 2 && pos > data.length / 2;
    }

    private void parseProtobuf(byte[] data) {
        parseProtobufRange(data, 0, data.length);
    }

    private void parseProtobufRange(byte[] data, int start, int end) {
        int pos = start;
        while (pos < end) {
            // Decode tag
            long[] tagResult = decodeVarint(data, pos, end);
            if (tagResult == null) {
                markRange(pos, end, Region.BINARY);
                return;
            }

            long tag = tagResult[0];
            int tagEnd = (int) tagResult[1];
            int wireType = (int) (tag & 0x7);

            markRange(pos, tagEnd, Region.STRUCTURE);
            pos = tagEnd;

            switch (wireType) {
                case 0: { // varint
                    long[] v = decodeVarint(data, pos, end);
                    if (v == null) { markRange(pos, end, Region.BINARY); return; }
                    markRange(pos, (int) v[1], Region.NUMBER);
                    pos = (int) v[1];
                    break;
                }
                case 1: { // 64-bit fixed
                    if (pos + 8 > end) { markRange(pos, end, Region.BINARY); return; }
                    markRange(pos, pos + 8, Region.NUMBER);
                    pos += 8;
                    break;
                }
                case 2: { // length-delimited
                    long[] l = decodeVarint(data, pos, end);
                    if (l == null) { markRange(pos, end, Region.BINARY); return; }
                    int lenEnd = (int) l[1];
                    long len = l[0];
                    markRange(pos, lenEnd, Region.STRUCTURE);

                    int contentStart = lenEnd;
                    int contentEnd = (int) Math.min(contentStart + len, end);

                    if (isLikelyText(data, contentStart, contentEnd)) {
                        markRange(contentStart, contentEnd, Region.STRING);
                    } else if (tryParseNestedProtobuf(data, contentStart, contentEnd)) {
                        // nested parse already filled regionMap
                    } else {
                        markRange(contentStart, contentEnd, Region.BINARY);
                    }
                    pos = contentEnd;
                    break;
                }
                case 5: { // 32-bit fixed
                    if (pos + 4 > end) { markRange(pos, end, Region.BINARY); return; }
                    markRange(pos, pos + 4, Region.NUMBER);
                    pos += 4;
                    break;
                }
                default:
                    markRange(pos, end, Region.BINARY);
                    return;
            }
        }
    }

    private boolean tryParseNestedProtobuf(byte[] data, int start, int end) {
        if (start >= end) return false;

        // Quick validation pass first
        int pos = start;
        int fieldsDecoded = 0;
        while (pos < end) {
            long[] tagResult = decodeVarint(data, pos, end);
            if (tagResult == null) return false;

            long tag = tagResult[0];
            int fieldNumber = (int) (tag >>> 3);
            int wireType = (int) (tag & 0x7);
            if (fieldNumber < 1 || fieldNumber > 536870911) return false;
            if (wireType != 0 && wireType != 1 && wireType != 2 && wireType != 5) return false;

            pos = (int) tagResult[1];
            switch (wireType) {
                case 0:
                    long[] v = decodeVarint(data, pos, end);
                    if (v == null) return false;
                    pos = (int) v[1];
                    break;
                case 1:
                    pos += 8;
                    if (pos > end) return false;
                    break;
                case 2:
                    long[] l = decodeVarint(data, pos, end);
                    if (l == null) return false;
                    long len = l[0];
                    pos = (int) l[1];
                    if (len < 0 || pos + len > end) return false;
                    pos += (int) len;
                    break;
                case 5:
                    pos += 4;
                    if (pos > end) return false;
                    break;
                default:
                    return false;
            }
            fieldsDecoded++;
        }

        if (fieldsDecoded < 1 || pos != end) return false;

        // Valid nested protobuf — now do the actual coloring pass
        parseProtobufRange(data, start, end);
        return true;
    }

    // ── Text vs binary fallback ────────────────────────────────────────

    private void parseTextBinary(byte[] data) {
        int runStart = -1;
        for (int i = 0; i < data.length; i++) {
            int b = data[i] & 0xFF;
            boolean isText = (b >= 32 && b <= 126) || b == '\r' || b == '\n' || b == '\t';

            if (isText) {
                if (runStart < 0) runStart = i;
            } else {
                if (runStart >= 0) {
                    Region r = (i - runStart) >= 4 ? Region.STRING : Region.BINARY;
                    markRange(runStart, i, r);
                    runStart = -1;
                }
                regionMap[i] = Region.BINARY;
            }
        }
        if (runStart >= 0) {
            Region r = (data.length - runStart) >= 4 ? Region.STRING : Region.BINARY;
            markRange(runStart, data.length, r);
        }
    }

    // ── Utility methods ────────────────────────────────────────────────

    private long[] decodeVarint(byte[] data, int pos, int limit) {
        long result = 0;
        int shift = 0;
        int i = pos;
        while (i < limit) {
            if (shift >= 64) return null;
            byte b = data[i];
            result |= (long) (b & 0x7F) << shift;
            i++;
            if ((b & 0x80) == 0) {
                return new long[]{result, i};
            }
            shift += 7;
        }
        return null;
    }

    private boolean isLikelyText(byte[] data, int start, int end) {
        if (start >= end) return false;
        int printable = 0;
        int len = end - start;
        for (int i = start; i < end; i++) {
            int b = data[i] & 0xFF;
            if ((b >= 32 && b <= 126) || b == '\r' || b == '\n' || b == '\t') {
                printable++;
            }
        }
        return len > 0 && (printable * 100 / len) >= 80;
    }

    private void markRange(int start, int end, Region region) {
        for (int i = start; i < end && i < regionMap.length; i++) {
            regionMap[i] = region;
        }
    }
}
