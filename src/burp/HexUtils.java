package burp;

/**
 * Utility class for hex string conversions.
 * Provides common hex encoding/decoding operations used throughout the extension.
 */
public final class HexUtils {

    private HexUtils() {
        // Utility class - prevent instantiation
    }

    /**
     * Parse a hex string into bytes.
     * Accepts various formats: "48656C6C6F", "48 65 6C 6C 6F", "48:65:6C:6C:6F", "48-65-6C-6C-6F"
     *
     * @param hex the hex string to parse
     * @return the decoded bytes, or null if the input is invalid
     */
    public static byte[] parseHexString(String hex) {
        if (hex == null) {
            return null;
        }

        // Remove common separators and whitespace
        hex = hex.replaceAll("[\\s,:\\-]", "");

        // Must be even length
        if (hex.length() % 2 != 0) {
            return null;
        }

        try {
            byte[] result = new byte[hex.length() / 2];
            for (int i = 0; i < result.length; i++) {
                result[i] = (byte) Integer.parseInt(hex.substring(i * 2, i * 2 + 2), 16);
            }
            return result;
        } catch (NumberFormatException e) {
            return null;
        }
    }

    /**
     * Convert bytes to a space-separated hex string.
     * Example: {0x48, 0x65, 0x6C} -> "48 65 6C"
     *
     * @param bytes the bytes to convert
     * @return the hex string representation
     */
    public static String toHexString(byte[] bytes) {
        if (bytes == null || bytes.length == 0) {
            return "";
        }

        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < bytes.length; i++) {
            if (i > 0) sb.append(' ');
            sb.append(String.format("%02X", bytes[i] & 0xFF));
        }
        return sb.toString();
    }

    /**
     * Convert bytes to a C-style array string.
     * Example: {0x48, 0x65, 0x6C} -> "\x48\x65\x6C"
     *
     * @param bytes the bytes to convert
     * @return the C array string representation
     */
    public static String toCArrayString(byte[] bytes) {
        if (bytes == null || bytes.length == 0) {
            return "";
        }

        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("\\x%02X", b & 0xFF));
        }
        return sb.toString();
    }
}
