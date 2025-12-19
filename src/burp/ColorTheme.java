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

    public static ColorTheme createMonokaiTheme() {
        return new ColorTheme("Monokai",
            new Color(248, 248, 242),           // printableColor (off-white)
            new Color(249, 38, 114),            // nullByteColor (pink)
            new Color(102, 217, 239),           // unprintableColor (cyan)
            new Color(248, 248, 242),           // spaceColor
            new Color(55, 55, 45),              // requestLineBg
            new Color(45, 50, 40),              // headersBg
            new Color(40, 42, 54),              // bodyBg
            new Color(39, 40, 34),              // defaultBg (monokai bg)
            null, null, null, null
        );
    }

    public static ColorTheme createSolarizedDarkTheme() {
        return new ColorTheme("Solarized Dark",
            new Color(131, 148, 150),           // printableColor (base0)
            new Color(220, 50, 47),             // nullByteColor (red)
            new Color(38, 139, 210),            // unprintableColor (blue)
            new Color(131, 148, 150),           // spaceColor
            new Color(7, 54, 66),               // requestLineBg (base02)
            new Color(0, 53, 63),               // headersBg
            new Color(0, 48, 58),               // bodyBg
            new Color(0, 43, 54),               // defaultBg (base03)
            null, null, null, null
        );
    }

    public static ColorTheme createSolarizedLightTheme() {
        return new ColorTheme("Solarized Light",
            new Color(101, 123, 131),           // printableColor (base00)
            new Color(220, 50, 47),             // nullByteColor (red)
            new Color(38, 139, 210),            // unprintableColor (blue)
            new Color(101, 123, 131),           // spaceColor
            new Color(238, 232, 213),           // requestLineBg (base2)
            new Color(245, 240, 225),           // headersBg
            new Color(250, 245, 235),           // bodyBg
            new Color(253, 246, 227),           // defaultBg (base3)
            null, null, null, null
        );
    }

    public static ColorTheme createMatrixTheme() {
        return new ColorTheme("Matrix",
            new Color(0, 255, 65),              // printableColor (matrix green)
            new Color(255, 0, 0),               // nullByteColor (red)
            new Color(0, 180, 45),              // unprintableColor (darker green)
            new Color(0, 200, 50),              // spaceColor
            new Color(0, 20, 5),                // requestLineBg
            new Color(0, 15, 3),                // headersBg
            new Color(0, 10, 2),                // bodyBg
            new Color(0, 5, 0),                 // defaultBg (almost black)
            null, null, null, null
        );
    }

    public static ColorTheme createDraculaTheme() {
        return new ColorTheme("Dracula",
            new Color(248, 248, 242),           // printableColor (foreground)
            new Color(255, 85, 85),             // nullByteColor (red)
            new Color(139, 233, 253),           // unprintableColor (cyan)
            new Color(248, 248, 242),           // spaceColor
            new Color(55, 60, 75),              // requestLineBg
            new Color(50, 55, 70),              // headersBg
            new Color(45, 50, 65),              // bodyBg
            new Color(40, 42, 54),              // defaultBg (background)
            null, null, null, null
        );
    }

    public static ColorTheme createOceanTheme() {
        return new ColorTheme("Ocean",
            new Color(220, 235, 250),           // printableColor (light blue-white)
            new Color(255, 100, 100),           // nullByteColor (coral)
            new Color(100, 200, 255),           // unprintableColor (sky blue)
            new Color(200, 220, 240),           // spaceColor
            new Color(25, 55, 85),              // requestLineBg (deep blue)
            new Color(20, 50, 80),              // headersBg
            new Color(15, 45, 75),              // bodyBg
            new Color(10, 40, 70),              // defaultBg (ocean blue)
            null, null, null, null
        );
    }

    public static ColorTheme createRetroTheme() {
        return new ColorTheme("Retro",
            new Color(255, 176, 0),             // printableColor (amber)
            new Color(255, 0, 0),               // nullByteColor (red)
            new Color(0, 255, 0),               // unprintableColor (green phosphor)
            new Color(255, 176, 0),             // spaceColor
            new Color(30, 25, 20),              // requestLineBg
            new Color(25, 20, 15),              // headersBg
            new Color(20, 15, 10),              // bodyBg
            new Color(15, 10, 5),               // defaultBg (dark brown)
            null, null, null, null
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
