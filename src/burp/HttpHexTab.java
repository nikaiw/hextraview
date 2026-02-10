package burp;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.ui.Selection;
import burp.api.montoya.ui.editor.extension.ExtensionProvidedHttpRequestEditor;
import burp.api.montoya.ui.editor.extension.ExtensionProvidedHttpResponseEditor;

import org.exbin.bined.SelectionRange;
import org.exbin.bined.swing.capability.ColorAssessorPainterCapable;
import org.exbin.auxiliary.binary_data.array.ByteArrayEditableData;

import java.awt.Component;
import java.util.Arrays;

/**
 * Montoya API hex editor tab for HTTP request and response messages.
 * Implements both editor interfaces — each instance is used in only one mode
 * (request or response) depending on which provider created it.
 */
public class HttpHexTab implements ExtensionProvidedHttpRequestEditor, ExtensionProvidedHttpResponseEditor {

    private final boolean isRequestMode;
    private final HextraCodeAreaPainter codeAreaPainter;
    private final SettingsManager settingsManager;
    private final HexviewCodeArea hexEditor;
    private final DeltaHexPanel hexPanel;
    private final ByteArrayEditableData data;
    private final HttpRegionParser regionParser;
    private byte[] originalContent;

    public HttpHexTab(MontoyaApi api, boolean isRequestMode) {
        this.isRequestMode = isRequestMode;
        this.settingsManager = new SettingsManager(api);

        this.hexPanel = new DeltaHexPanel();
        this.hexEditor = new HexviewCodeArea();

        this.codeAreaPainter = new HextraCodeAreaPainter(hexEditor);
        codeAreaPainter.buildUnprintableCharactersMapping();

        this.regionParser = new HttpRegionParser();
        codeAreaPainter.setRegionParser(regionParser);

        this.data = new ByteArrayEditableData();
        hexEditor.setContentData(data);

        if (hexEditor.getPainter() instanceof ColorAssessorPainterCapable) {
            ((ColorAssessorPainterCapable) hexEditor.getPainter()).setColorAssessor(codeAreaPainter);
        }

        this.hexPanel.setColorAssessor(codeAreaPainter);
        this.hexPanel.setSettingsManager(settingsManager);
        this.hexPanel.setCodeArea(hexEditor);
    }

    @Override
    public void setRequestResponse(HttpRequestResponse requestResponse) {
        byte[] content;
        if (isRequestMode) {
            content = requestResponse.request().toByteArray().getBytes();
        } else {
            if (requestResponse.response() != null) {
                content = requestResponse.response().toByteArray().getBytes();
            } else {
                content = new byte[0];
            }
        }

        if (content == null) {
            content = new byte[0];
        }

        this.originalContent = content.clone();

        this.regionParser.parse(content);
        this.codeAreaPainter.setRegionParser(regionParser);

        this.data.clear();
        if (content.length > 0) {
            this.data.insert(0, content);
        }
        this.hexEditor.setContentData(this.data);
        this.hexEditor.clearUndoHistory();
        this.hexEditor.repaint();
        this.hexPanel.updateRawView();
    }

    @Override
    public boolean isEnabledFor(HttpRequestResponse requestResponse) {
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
    public HttpRequest getRequest() {
        return HttpRequest.httpRequest(ByteArray.byteArray(this.data.getData()));
    }

    @Override
    public HttpResponse getResponse() {
        return HttpResponse.httpResponse(ByteArray.byteArray(this.data.getData()));
    }

    @Override
    public boolean isModified() {
        if (originalContent == null) {
            return false;
        }
        byte[] current = this.data.getData();
        if (current == null) {
            return originalContent.length > 0;
        }
        return !Arrays.equals(current, originalContent);
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
