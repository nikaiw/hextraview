package burp;

import java.awt.Color;

/**
 * Represents a color theme for the hex editor.
 * Contains all configurable colors for character types and HTTP regions.
 */
public class ColorTheme {
    private String name;

    // Text colors for character types
    private Color printableColor;
    private Color nullByteColor;
    private Color unprintableColor;
    private Color spaceColor;

    // Region background colors
    private Color requestLineBg;
    private Color headersBg;
    private Color bodyBg;
    private Color defaultBg;

    // Character background colors (null = use region background)
    private Color printableBg;
    private Color nullByteBg;
    private Color unprintableBg;
    private Color spaceBg;

    public ColorTheme(String name) {
        this.name = name;
    }

    // Create a theme with all colors specified
    public ColorTheme(String name,
                      Color printableColor, Color nullByteColor, Color unprintableColor, Color spaceColor,
                      Color requestLineBg, Color headersBg, Color bodyBg, Color defaultBg,
                      Color printableBg, Color nullByteBg, Color unprintableBg, Color spaceBg) {
        this.name = name;
        this.printableColor = printableColor;
        this.nullByteColor = nullByteColor;
        this.unprintableColor = unprintableColor;
        this.spaceColor = spaceColor;
        this.requestLineBg = requestLineBg;
        this.headersBg = headersBg;
        this.bodyBg = bodyBg;
        this.defaultBg = defaultBg;
        this.printableBg = printableBg;
        this.nullByteBg = nullByteBg;
        this.unprintableBg = unprintableBg;
        this.spaceBg = spaceBg;
    }

    // Preset themes
    public static ColorTheme createLightTheme() {
        return new ColorTheme("Light",
            Color.BLACK,                        // printableColor
            Color.RED,                          // nullByteColor
            Color.BLUE,                         // unprintableColor
            Color.BLACK,                        // spaceColor
            new Color(255, 245, 238),           // requestLineBg (Seashell)
            new Color(240, 255, 240),           // headersBg (Honeydew)
            new Color(240, 248, 255),           // bodyBg (AliceBlue)
            Color.WHITE,                        // defaultBg
            null, null, null, null              // character backgrounds (use region)
        );
    }

    public static ColorTheme createDarkTheme() {
        return new ColorTheme("Dark",
            new Color(200, 200, 200),           // printableColor (light gray)
            new Color(255, 100, 100),           // nullByteColor (soft red)
            new Color(100, 150, 255),           // unprintableColor (soft blue)
            new Color(200, 200, 200),           // spaceColor (light gray)
            new Color(50, 45, 55),              // requestLineBg (dark purple-ish)
            new Color(40, 50, 40),              // headersBg (dark green)
            new Color(40, 45, 55),              // bodyBg (dark blue)
            new Color(35, 35, 35),              // defaultBg (dark gray)
            null, null, null, null              // character backgrounds (use region)
        );
    }

    public static ColorTheme createHighContrastTheme() {
        return new ColorTheme("High Contrast",
            Color.BLACK,                        // printableColor
            new Color(220, 0, 0),               // nullByteColor (bright red)
            new Color(0, 0, 220),               // unprintableColor (bright blue)
            Color.BLACK,                        // spaceColor
            new Color(255, 255, 200),           // requestLineBg (bright yellow)
            new Color(200, 255, 200),           // headersBg (bright green)
            new Color(200, 200, 255),           // bodyBg (bright blue)
            Color.WHITE,                        // defaultBg
            null, null, null, null              // character backgrounds (use region)
        );
    }

    // Getters and setters
    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public Color getPrintableColor() {
        return printableColor;
    }

    public void setPrintableColor(Color printableColor) {
        this.printableColor = printableColor;
    }

    public Color getNullByteColor() {
        return nullByteColor;
    }

    public void setNullByteColor(Color nullByteColor) {
        this.nullByteColor = nullByteColor;
    }

    public Color getUnprintableColor() {
        return unprintableColor;
    }

    public void setUnprintableColor(Color unprintableColor) {
        this.unprintableColor = unprintableColor;
    }

    public Color getSpaceColor() {
        return spaceColor;
    }

    public void setSpaceColor(Color spaceColor) {
        this.spaceColor = spaceColor;
    }

    public Color getRequestLineBg() {
        return requestLineBg;
    }

    public void setRequestLineBg(Color requestLineBg) {
        this.requestLineBg = requestLineBg;
    }

    public Color getHeadersBg() {
        return headersBg;
    }

    public void setHeadersBg(Color headersBg) {
        this.headersBg = headersBg;
    }

    public Color getBodyBg() {
        return bodyBg;
    }

    public void setBodyBg(Color bodyBg) {
        this.bodyBg = bodyBg;
    }

    public Color getDefaultBg() {
        return defaultBg;
    }

    public void setDefaultBg(Color defaultBg) {
        this.defaultBg = defaultBg;
    }

    public Color getPrintableBg() {
        return printableBg;
    }

    public void setPrintableBg(Color printableBg) {
        this.printableBg = printableBg;
    }

    public Color getNullByteBg() {
        return nullByteBg;
    }

    public void setNullByteBg(Color nullByteBg) {
        this.nullByteBg = nullByteBg;
    }

    public Color getUnprintableBg() {
        return unprintableBg;
    }

    public void setUnprintableBg(Color unprintableBg) {
        this.unprintableBg = unprintableBg;
    }

    public Color getSpaceBg() {
        return spaceBg;
    }

    public void setSpaceBg(Color spaceBg) {
        this.spaceBg = spaceBg;
    }

    @Override
    public String toString() {
        return name;
    }
}
