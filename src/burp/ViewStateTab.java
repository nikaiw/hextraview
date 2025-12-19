package burp;

import org.exbin.bined.SelectionRange;
import org.exbin.bined.swing.basic.CodeArea;
import org.exbin.bined.swing.capability.ColorAssessorPainterCapable;
import org.exbin.auxiliary.binary_data.array.ByteArrayEditableData;

import java.awt.*;
import java.util.Arrays;


public class ViewStateTab implements IMessageEditorTab {
    private final IBurpExtenderCallbacks callbacks;
    private final IExtensionHelpers helpers;
    private final HextraCodeAreaPainter codeAreaPainter;
    private final SettingsManager settingsManager;
    private CodeArea hexEditor;
    private DeltaHexPanel hexPanel;
    private ByteArrayEditableData data;
    private HttpRegionParser regionParser;
    private byte[] originalContent;

    public ViewStateTab(IBurpExtenderCallbacks callbacks, IMessageEditorController controller, boolean editable) {
        this.callbacks = callbacks;
        this.helpers = callbacks.getHelpers();
        this.settingsManager = new SettingsManager(callbacks);

        this.hexPanel = new DeltaHexPanel();
        hexEditor = new HexviewCodeArea();

        // Create and configure the custom painter
        this.codeAreaPainter = new HextraCodeAreaPainter(hexEditor);
        codeAreaPainter.buildUnprintableCharactersMapping();

        // Create the region parser
        this.regionParser = new HttpRegionParser();
        codeAreaPainter.setRegionParser(regionParser);

        this.data = new ByteArrayEditableData();
        hexEditor.setContentData(data);

        // Set our custom color assessor on the default painter
        if (hexEditor.getPainter() instanceof ColorAssessorPainterCapable) {
            ((ColorAssessorPainterCapable) hexEditor.getPainter()).setColorAssessor(codeAreaPainter);
        }

        // Set up color assessor and settings manager BEFORE setCodeArea (order matters!)
        this.hexPanel.setColorAssessor(codeAreaPainter);
        this.hexPanel.setSettingsManager(settingsManager);

        // Now set the code area (this sets up listeners that need the painter)
        this.hexPanel.setCodeArea(hexEditor);
    }

    @Override
    public String getTabCaption() {
        return "Hextraview";
    }

    @Override
    public Component getUiComponent() {
        return this.hexPanel;
    }

    @Override
    public boolean isEnabled(byte[] content, boolean isRequest) {
        return true;
    }

    @Override
    public void setMessage(byte[] content, boolean isRequest) {
        if (content == null) {
            content = new byte[0];
        }

        // Store original content for modification detection
        this.originalContent = content.clone();

        // Parse HTTP regions
        this.regionParser.parse(content);
        this.codeAreaPainter.setRegionParser(regionParser);

        // Update hex editor data
        this.data.clear();
        if (content.length > 0) {
            this.data.insert(0, content);
        }
        this.hexEditor.setContentData(this.data);
        this.hexEditor.repaint();

        // Sync raw view
        this.hexPanel.updateRawView();
    }

    @Override
    public byte[] getMessage() {
        return this.data.getData();
    }

    @Override
    public boolean isModified() {
        if (originalContent == null) {
            return false;
        }
        byte[] currentContent = this.data.getData();
        if (currentContent == null) {
            return originalContent.length > 0;
        }
        if (currentContent.length != originalContent.length) {
            return true;
        }
        for (int i = 0; i < currentContent.length; i++) {
            if (currentContent[i] != originalContent[i]) {
                return true;
            }
        }
        return false;
    }

    @Override
    public byte[] getSelectedData() {
        SelectionRange selected = this.hexEditor.getSelection();
        if (selected == null) {
            return new byte[0];
        }
        int start = (int) selected.getStart();
        int end = (int) selected.getEnd();
        byte[] allData = this.data.getData();
        if (start >= 0 && end <= allData.length && start < end) {
            return Arrays.copyOfRange(allData, start, end);
        }
        return new byte[0];
    }
}
