package burp;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.persistence.PersistedObject;

import java.awt.Color;

public class SettingsManager {
    private final IBurpExtenderCallbacks callbacks;
    private final PersistedObject storage;
    private static final String PREFIX = "hextraview.";

    // Setting keys
    public static final String KEY_VIEW_MODE = "viewMode";
    public static final String KEY_CODE_TYPE = "codeType";
    public static final String KEY_FONT_FAMILY = "fontFamily";
    public static final String KEY_FONT_SIZE = "fontSize";
    public static final String KEY_CHARSET = "charset";
    public static final String KEY_CHAR_RENDERING = "charRendering";
    public static final String KEY_CHAR_ANTIALIASING = "charAntialiasing";
    public static final String KEY_EDITATION_ALLOWED = "editationAllowed";
    public static final String KEY_SHOW_LINE_NUMBERS = "showLineNumbers";
    public static final String KEY_SHOW_HEADER = "showHeader";
    public static final String KEY_SHOW_NONPRINTABLE = "showNonprintable";
    public static final String KEY_LINE_LENGTH = "lineLength";
    public static final String KEY_LINE_NUMBERS_LENGTH = "lineNumbersLength";
    public static final String KEY_LINE_NUMBERS_SPACE = "lineNumbersSpace";
    public static final String KEY_HEADER_SPACE = "headerSpace";
    public static final String KEY_BYTE_GROUP_SIZE = "byteGroupSize";
    public static final String KEY_SPACE_GROUP_SIZE = "spaceGroupSize";
    public static final String KEY_WRAP_LINE_MODE = "wrapLineMode";
    public static final String KEY_BACKGROUND_MODE = "backgroundMode";
    public static final String KEY_LINE_NUMBERS_BACKGROUND = "lineNumbersBackground";
    public static final String KEY_HEX_CHARACTERS_MODE = "hexCharactersMode";
    public static final String KEY_POSITION_CODE_TYPE = "positionCodeType";
    public static final String KEY_DECORATOR_HEADER_LINE = "decoratorHeaderLine";
    public static final String KEY_DECORATOR_LINENUM_LINE = "decoratorLinenumLine";
    public static final String KEY_DECORATOR_PREVIEW_LINE = "decoratorPreviewLine";
    public static final String KEY_DECORATOR_BOX = "decoratorBox";
    public static final String KEY_BORDER_TYPE = "borderType";
    public static final String KEY_VERTICAL_SCROLLBAR = "verticalScrollbar";
    public static final String KEY_HORIZONTAL_SCROLLBAR = "horizontalScrollbar";
    public static final String KEY_VERTICAL_SCROLL_MODE = "verticalScrollMode";
    public static final String KEY_HORIZONTAL_SCROLL_MODE = "horizontalScrollMode";
    public static final String KEY_CURSOR_RENDERING_MODE = "cursorRenderingMode";
    public static final String KEY_CURSOR_BLINK_RATE = "cursorBlinkRate";
    public static final String KEY_SHOW_SHADOW_CURSOR = "showShadowCursor";
    public static final String KEY_INSERT_CURSOR_SHAPE = "insertCursorShape";
    public static final String KEY_OVERWRITE_CURSOR_SHAPE = "overwriteCursorShape";
    public static final String KEY_SETTINGS_COLLAPSED = "settingsCollapsed";
    public static final String KEY_SETTINGS_DIVIDER_LOCATION = "settingsDividerLocation";

    // Color keys - text colors
    public static final String KEY_PRINTABLE_COLOR = "printableColor";
    public static final String KEY_NULL_BYTE_COLOR = "nullByteColor";
    public static final String KEY_UNPRINTABLE_COLOR = "unprintableColor";
    public static final String KEY_SPACE_COLOR = "spaceColor";

    // Color keys - character background colors (null/empty = use region bg)
    public static final String KEY_PRINTABLE_BG = "printableBgColor";
    public static final String KEY_NULL_BYTE_BG = "nullByteBgColor";
    public static final String KEY_UNPRINTABLE_BG = "unprintableBgColor";
    public static final String KEY_SPACE_BG = "spaceBgColor";

    // Color keys - region background colors
    public static final String KEY_REGION_COLORING_ENABLED = "regionColoringEnabled";
    public static final String KEY_REQUEST_LINE_BG = "requestLineBgColor";
    public static final String KEY_HEADERS_BG = "headersBgColor";
    public static final String KEY_BODY_BG = "bodyBgColor";
    public static final String KEY_DEFAULT_BG = "defaultBgColor";

    // Color keys - WebSocket region background colors
    public static final String KEY_WS_COLORING_ENABLED = "wsColoringEnabled";
    public static final String KEY_WS_KEY_BG = "wsKeyBgColor";
    public static final String KEY_WS_STRING_BG = "wsStringBgColor";
    public static final String KEY_WS_NUMBER_BG = "wsNumberBgColor";
    public static final String KEY_WS_STRUCTURE_BG = "wsStructureBgColor";
    public static final String KEY_WS_LITERAL_BG = "wsLiteralBgColor";
    public static final String KEY_WS_BINARY_BG = "wsBinaryBgColor";
    public static final String KEY_WS_DEFAULT_BG = "wsDefaultBgColor";

    // Theme key
    public static final String KEY_CURRENT_THEME = "currentTheme";

    public SettingsManager(IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;
        this.storage = null;
    }

    public SettingsManager(MontoyaApi api) {
        this.callbacks = null;
        this.storage = api.persistence().extensionData();
    }

    public void saveSetting(String key, String value) {
        if (storage != null) {
            if (value != null) {
                storage.setString(PREFIX + key, value);
            } else {
                storage.deleteString(PREFIX + key);
            }
        } else if (callbacks != null) {
            callbacks.saveExtensionSetting(PREFIX + key, value);
        }
    }

    public void clearSetting(String key) {
        if (storage != null) {
            storage.deleteString(PREFIX + key);
        } else if (callbacks != null) {
            callbacks.saveExtensionSetting(PREFIX + key, null);
        }
    }

    public String loadSetting(String key, String defaultValue) {
        String value = null;
        if (storage != null) {
            value = storage.getString(PREFIX + key);
        } else if (callbacks != null) {
            value = callbacks.loadExtensionSetting(PREFIX + key);
        }
        return value != null ? value : defaultValue;
    }

    public void saveInt(String key, int value) {
        saveSetting(key, String.valueOf(value));
    }

    public int loadInt(String key, int defaultValue) {
        try {
            return Integer.parseInt(loadSetting(key, String.valueOf(defaultValue)));
        } catch (NumberFormatException e) {
            return defaultValue;
        }
    }

    public void saveBoolean(String key, boolean value) {
        saveSetting(key, String.valueOf(value));
    }

    public boolean loadBoolean(String key, boolean defaultValue) {
        String value = loadSetting(key, null);
        if (value == null) {
            return defaultValue;
        }
        return Boolean.parseBoolean(value);
    }

    public void saveColor(String key, Color color) {
        if (color != null) {
            saveSetting(key, String.valueOf(color.getRGB()));
        }
    }

    public Color loadColor(String key, Color defaultColor) {
        String value = loadSetting(key, null);
        if (value == null) {
            return defaultColor;
        }
        try {
            return new Color(Integer.parseInt(value));
        } catch (NumberFormatException e) {
            return defaultColor;
        }
    }
}
