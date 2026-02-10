package burp;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.ui.Selection;
import burp.api.montoya.ui.contextmenu.WebSocketMessage;
import burp.api.montoya.ui.editor.extension.ExtensionProvidedWebSocketMessageEditor;

import org.exbin.bined.SelectionRange;
import org.exbin.bined.swing.capability.ColorAssessorPainterCapable;
import org.exbin.auxiliary.binary_data.array.ByteArrayEditableData;

import java.awt.Component;
import java.util.Arrays;

/**
 * Hex editor tab for WebSocket messages in Burp Suite.
 * Implements the Montoya API's WebSocket message editor interface
 * using the same hex editor components as the HTTP {@link HttpHexTab}.
 */
public class WebSocketHexTab implements ExtensionProvidedWebSocketMessageEditor {

    private final HextraCodeAreaPainter codeAreaPainter;
    private final WebSocketPayloadParser wsParser;
    private final SettingsManager settingsManager;
    private final HexviewCodeArea hexEditor;
    private final DeltaHexPanel hexPanel;
    private final ByteArrayEditableData data;
    private byte[] originalPayload;

    public WebSocketHexTab(MontoyaApi api) {
        this.settingsManager = new SettingsManager(api);

        this.hexPanel = new DeltaHexPanel();
        this.hexEditor = new HexviewCodeArea();

        // Create and configure the custom painter with WebSocket payload parser
        this.codeAreaPainter = new HextraCodeAreaPainter(hexEditor);
        codeAreaPainter.buildUnprintableCharactersMapping();
        this.wsParser = new WebSocketPayloadParser();
        codeAreaPainter.setWsParser(wsParser);

        this.data = new ByteArrayEditableData();
        hexEditor.setContentData(data);

        if (hexEditor.getPainter() instanceof ColorAssessorPainterCapable) {
            ((ColorAssessorPainterCapable) hexEditor.getPainter()).setColorAssessor(codeAreaPainter);
        }

        this.hexPanel.setColorAssessor(codeAreaPainter);
        this.hexPanel.setSettingsManager(settingsManager);
        this.hexPanel.setWebSocketMode(true);
        this.hexPanel.setCodeArea(hexEditor);
    }

    @Override
    public void setMessage(WebSocketMessage message) {
        byte[] payload;
        if (message == null || message.payload() == null) {
            payload = new byte[0];
        } else {
            payload = message.payload().getBytes();
        }

        this.originalPayload = payload.clone();

        // Parse payload structure for syntax-aware coloring
        this.wsParser.parse(payload);

        this.data.clear();
        if (payload.length > 0) {
            this.data.insert(0, payload);
        }
        this.hexEditor.setContentData(this.data);
        this.hexEditor.clearUndoHistory();
        this.hexEditor.repaint();
        this.hexPanel.updateRawView();
    }

    @Override
    public boolean isEnabledFor(WebSocketMessage message) {
        return true;
    }

    @Override
    public String caption() {
        return "Hextraview";
    }

    @Override
    public Component uiComponent() {
        return this.hexPanel;
    }

    @Override
    public ByteArray getMessage() {
        return ByteArray.byteArray(this.data.getData());
    }

    @Override
    public boolean isModified() {
        if (originalPayload == null) {
            return false;
        }
        byte[] current = this.data.getData();
        if (current == null) {
            return originalPayload.length > 0;
        }
        return !Arrays.equals(current, originalPayload);
    }

    @Override
    public Selection selectedData() {
        SelectionRange selected = this.hexEditor.getSelection();
        if (selected == null) {
            return null;
        }
        int start = (int) selected.getStart();
        int end = (int) selected.getEnd();
        byte[] allData = this.data.getData();
        if (start >= 0 && end <= allData.length && start < end) {
            byte[] selectedBytes = Arrays.copyOfRange(allData, start, end);
            return Selection.selection(ByteArray.byteArray(selectedBytes), start, end);
        }
        return null;
    }
}
