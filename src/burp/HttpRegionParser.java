package burp;

public class HttpRegionParser {

    public enum Region {
        REQUEST_LINE,  // First line (before first \r\n)
        HEADERS,       // Between first \r\n and \r\n\r\n
        BODY           // After \r\n\r\n
    }

    private int requestLineEnd = -1;   // Position of first \r\n
    private int headersEnd = -1;       // Position of \r\n\r\n (start of body separator)
    private int bodyStart = -1;        // Position after \r\n\r\n
    private int contentLength = 0;

    public HttpRegionParser() {
    }

    public void parse(byte[] content) {
        if (content == null || content.length == 0) {
            requestLineEnd = -1;
            headersEnd = -1;
            bodyStart = -1;
            contentLength = 0;
            return;
        }

        contentLength = content.length;
        requestLineEnd = -1;
        headersEnd = -1;
        bodyStart = -1;

        int lastCrLf = -2;  // Track position of last \r\n

        for (int i = 0; i < content.length - 1; i++) {
            if (content[i] == '\r' && content[i + 1] == '\n') {
                if (requestLineEnd < 0) {
                    // First \r\n marks end of request line
                    requestLineEnd = i;
                } else if (i == lastCrLf + 2) {
                    // Found \r\n\r\n (consecutive CRLF)
                    headersEnd = i;
                    bodyStart = i + 2;
                    break;
                }
                lastCrLf = i;
            }
        }

        // Handle case where there's only request line (no \r\n\r\n found)
        if (requestLineEnd >= 0 && headersEnd < 0) {
            // Everything after first \r\n is considered headers
            headersEnd = content.length;
            bodyStart = content.length;
        }

        // Handle case where there's no \r\n at all
        if (requestLineEnd < 0) {
            // Treat entire content as request line
            requestLineEnd = content.length;
            headersEnd = content.length;
            bodyStart = content.length;
        }
    }

    public Region getRegionForPosition(long position) {
        if (position < 0) {
            return Region.REQUEST_LINE;
        }

        // Before first \r\n -> request line
        if (position < requestLineEnd) {
            return Region.REQUEST_LINE;
        }

        // Between first \r\n and \r\n\r\n -> headers
        // Include the \r\n after request line in headers region
        if (position < headersEnd + 2 && position < bodyStart) {
            return Region.HEADERS;
        }

        // After \r\n\r\n -> body
        return Region.BODY;
    }

    public int getRequestLineEnd() {
        return requestLineEnd;
    }

    public int getHeadersEnd() {
        return headersEnd;
    }

    public int getBodyStart() {
        return bodyStart;
    }

    public int getContentLength() {
        return contentLength;
    }

    public boolean hasBody() {
        return bodyStart >= 0 && bodyStart < contentLength;
    }

    public boolean hasHeaders() {
        return requestLineEnd >= 0 && requestLineEnd < headersEnd;
    }
}
