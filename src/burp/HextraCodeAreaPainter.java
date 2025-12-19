package burp;

import org.exbin.bined.swing.basic.CodeArea;
import org.exbin.bined.swing.CodeAreaColorAssessor;
import org.exbin.bined.swing.CodeAreaPaintState;
import org.exbin.bined.CodeAreaSection;
import org.exbin.auxiliary.binary_data.BinaryData;

import java.awt.*;
import java.util.HashMap;
import java.util.Optional;

/**
 * Custom color assessor for the hex editor that provides:
 * - Character type coloring (printable, null, unprintable)
 * - HTTP region background coloring
 */
public class HextraCodeAreaPainter implements CodeAreaColorAssessor {

    // Character type classification
    public enum CharType { PRINTABLE, NULL_BYTE, UNPRINTABLE }

    // Reference to the code area
    private CodeArea codeArea;

    // Character type mapping
    private HashMap<Character, CharType> characterTypeMapping;

    // Unprintable character visual mapping
    private HashMap<Character, Character> unprintableCharactersMapping;

    // Configurable character text colors
    private Color printableColor = Color.BLACK;
    private Color nullByteColor = Color.RED;
    private Color unprintableColor = Color.BLUE;
    private Color spaceColor = Color.BLACK;

    // Character background colors (null = use region background)
    private Color printableBgColor = null;
    private Color nullByteBgColor = null;
    private Color unprintableBgColor = null;
    private Color spaceBgColor = null;

    // HTTP region parser and colors
    private HttpRegionParser regionParser;
    private Color requestLineBg = new Color(255, 245, 238);  // Seashell
    private Color headersBg = new Color(240, 255, 240);      // Honeydew
    private Color bodyBg = new Color(240, 248, 255);         // AliceBlue
    private Color defaultBg = new Color(255, 255, 255);      // White
    private boolean regionColoringEnabled = true;

    public HextraCodeAreaPainter(CodeArea codeArea) {
        this.codeArea = codeArea;
        buildCharacterTypeMapping();
        buildUnprintableCharactersMapping();
    }

    public void buildCharacterTypeMapping() {
        characterTypeMapping = new HashMap<>();
        // Null byte
        characterTypeMapping.put('\0', CharType.NULL_BYTE);
        // Printable characters (ASCII 32-126)
        for (char c = 32; c <= 126; c++) {
            characterTypeMapping.put(c, CharType.PRINTABLE);
        }
        // Unprintable characters (control characters 1-31, DEL 127)
        for (char c = 1; c <= 31; c++) {
            characterTypeMapping.put(c, CharType.UNPRINTABLE);
        }
        characterTypeMapping.put((char) 127, CharType.UNPRINTABLE);
    }

    public void buildUnprintableCharactersMapping() {
        unprintableCharactersMapping = new HashMap<>();
        // Unicode control character symbols
        for (int i = 0; i < 32; i++) {
            unprintableCharactersMapping.put((char) i, Character.toChars(9216 + i)[0]);
        }
        // Tab -> Right-Pointing Double Angle Quotation Mark
        unprintableCharactersMapping.put('\t', Character.toChars(187)[0]);
        // Carriage Return -> Currency Sign
        unprintableCharactersMapping.put('\r', Character.toChars(164)[0]);
        // Line Feed -> Pilcrow Sign
        unprintableCharactersMapping.put('\n', Character.toChars(182)[0]);
        // DEL -> Degree Sign
        unprintableCharactersMapping.put((char) 127, Character.toChars(176)[0]);
    }

    public CharType getCharacterType(char c) {
        CharType type = characterTypeMapping.get(c);
        if (type != null) {
            return type;
        }
        // Characters outside basic ASCII (128-255) treated as unprintable
        if (c > 127) {
            return CharType.UNPRINTABLE;
        }
        return CharType.PRINTABLE;
    }

    // Get color for a character based on its type
    public Color getColorForChar(char data) {
        CharType type = getCharacterType(data);
        switch (type) {
            case PRINTABLE:
                return printableColor;
            case NULL_BYTE:
                return nullByteColor;
            case UNPRINTABLE:
                return unprintableColor;
            default:
                return printableColor;
        }
    }

    // Setters for configurable character colors
    public void setPrintableColor(Color color) {
        this.printableColor = color;
    }

    public void setNullByteColor(Color color) {
        this.nullByteColor = color;
    }

    public void setUnprintableColor(Color color) {
        this.unprintableColor = color;
    }

    public void setSpaceColor(Color color) {
        this.spaceColor = color;
    }

    public Color getSpaceColor() {
        return spaceColor;
    }

    public void setCharacterColors(Color printable, Color nullByte, Color unprintable) {
        this.printableColor = printable;
        this.nullByteColor = nullByte;
        this.unprintableColor = unprintable;
    }

    // Getters for current colors
    public Color getPrintableColor() {
        return printableColor;
    }

    public Color getNullByteColor() {
        return nullByteColor;
    }

    public Color getUnprintableColor() {
        return unprintableColor;
    }

    // Character background color setters/getters
    public void setPrintableBgColor(Color color) {
        this.printableBgColor = color;
    }

    public Color getPrintableBgColor() {
        return printableBgColor;
    }

    public void setNullByteBgColor(Color color) {
        this.nullByteBgColor = color;
    }

    public Color getNullByteBgColor() {
        return nullByteBgColor;
    }

    public void setUnprintableBgColor(Color color) {
        this.unprintableBgColor = color;
    }

    public Color getUnprintableBgColor() {
        return unprintableBgColor;
    }

    public void setSpaceBgColor(Color color) {
        this.spaceBgColor = color;
    }

    public Color getSpaceBgColor() {
        return spaceBgColor;
    }

    // Get background color for a specific character
    public Color getBackgroundForChar(char c, long dataPosition) {
        Color regionBg = getRegionBackgroundColor(dataPosition);

        // Check for space character
        if (c == ' ') {
            return spaceBgColor != null ? spaceBgColor : regionBg;
        }

        CharType type = getCharacterType(c);
        switch (type) {
            case PRINTABLE:
                return printableBgColor != null ? printableBgColor : regionBg;
            case NULL_BYTE:
                return nullByteBgColor != null ? nullByteBgColor : regionBg;
            case UNPRINTABLE:
                return unprintableBgColor != null ? unprintableBgColor : regionBg;
            default:
                return regionBg;
        }
    }

    // HTTP region support
    public void setRegionParser(HttpRegionParser parser) {
        this.regionParser = parser;
    }

    public HttpRegionParser getRegionParser() {
        return regionParser;
    }

    public void setRegionColoringEnabled(boolean enabled) {
        this.regionColoringEnabled = enabled;
    }

    public boolean isRegionColoringEnabled() {
        return regionColoringEnabled;
    }

    public void setRequestLineBgColor(Color color) {
        this.requestLineBg = color;
    }

    public void setHeadersBgColor(Color color) {
        this.headersBg = color;
    }

    public void setBodyBgColor(Color color) {
        this.bodyBg = color;
    }

    public void setDefaultBgColor(Color color) {
        this.defaultBg = color;
    }

    public void setRegionColors(Color requestLine, Color headers, Color body, Color defaultBg) {
        this.requestLineBg = requestLine;
        this.headersBg = headers;
        this.bodyBg = body;
        this.defaultBg = defaultBg;
    }

    public Color getRequestLineBgColor() {
        return requestLineBg;
    }

    public Color getHeadersBgColor() {
        return headersBg;
    }

    public Color getBodyBgColor() {
        return bodyBg;
    }

    public Color getDefaultBgColor() {
        return defaultBg;
    }

    public Color getRegionBackgroundColor(long dataPosition) {
        if (!regionColoringEnabled) {
            return defaultBg;
        }
        if (regionParser == null) {
            return defaultBg;
        }
        HttpRegionParser.Region region = regionParser.getRegionForPosition(dataPosition);
        switch (region) {
            case REQUEST_LINE:
                return requestLineBg;
            case HEADERS:
                return headersBg;
            case BODY:
                return bodyBg;
            default:
                return defaultBg;
        }
    }

    // CodeAreaColorAssessor implementation
    @Override
    public Color getPositionTextColor(long rowDataPosition, int byteOnRow, int charOnRow,
                                       CodeAreaSection section, boolean inSelection) {
        if (inSelection) {
            // Use default selection text color
            return null;
        }

        // Calculate actual byte position: row start + byte offset on row
        long dataPosition = rowDataPosition + byteOnRow;

        BinaryData data = codeArea.getContentData();
        if (data != null && dataPosition < data.getDataSize()) {
            byte b = data.getByte(dataPosition);
            char c = (char) (b & 0xFF);

            // Check for space character first
            if (c == ' ') {
                return spaceColor;
            }

            CharType type = getCharacterType(c);
            switch (type) {
                case NULL_BYTE:
                    return nullByteColor;
                case UNPRINTABLE:
                    return unprintableColor;
                case PRINTABLE:
                default:
                    return printableColor;
            }
        }
        return printableColor;
    }

    @Override
    public Color getPositionBackgroundColor(long rowDataPosition, int byteOnRow, int charOnRow,
                                             CodeAreaSection section, boolean inSelection) {
        if (inSelection) {
            // Use default selection background
            return null;
        }

        // Calculate actual byte position: row start + byte offset on row
        long dataPosition = rowDataPosition + byteOnRow;

        BinaryData data = codeArea.getContentData();
        if (data != null && dataPosition < data.getDataSize()) {
            byte b = data.getByte(dataPosition);
            char c = (char) (b & 0xFF);
            return getBackgroundForChar(c, dataPosition);
        }
        return getRegionBackgroundColor(dataPosition);
    }

    @Override
    public Optional<CodeAreaColorAssessor> getParentColorAssessor() {
        return Optional.empty();
    }

    @Override
    public void startPaint(CodeAreaPaintState paintState) {
        // No initialization needed for each paint cycle
    }

    // Apply theme colors
    public void applyTheme(ColorTheme theme) {
        if (theme == null) return;

        // Text colors
        if (theme.getPrintableColor() != null) setPrintableColor(theme.getPrintableColor());
        if (theme.getNullByteColor() != null) setNullByteColor(theme.getNullByteColor());
        if (theme.getUnprintableColor() != null) setUnprintableColor(theme.getUnprintableColor());

        // Region backgrounds
        if (theme.getRequestLineBg() != null) setRequestLineBgColor(theme.getRequestLineBg());
        if (theme.getHeadersBg() != null) setHeadersBgColor(theme.getHeadersBg());
        if (theme.getBodyBg() != null) setBodyBgColor(theme.getBodyBg());
        if (theme.getDefaultBg() != null) setDefaultBgColor(theme.getDefaultBg());

        // Character backgrounds (can be null)
        setPrintableBgColor(theme.getPrintableBg());
        setNullByteBgColor(theme.getNullByteBg());
        setUnprintableBgColor(theme.getUnprintableBg());
        setSpaceBgColor(theme.getSpaceBg());
    }

    // Get unprintable character mapping for display
    public HashMap<Character, Character> getUnprintableCharactersMapping() {
        return unprintableCharactersMapping;
    }
}
