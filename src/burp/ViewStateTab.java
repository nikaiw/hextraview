package burp;
import org.exbin.deltahex.SelectionRange;
import org.exbin.deltahex.swing.CodeArea;
import org.exbin.utils.binary_data.ByteArrayEditableData;
import java.awt.*;
import java.util.Arrays;


public class ViewStateTab implements IMessageEditorTab {
    private final IExtensionHelpers helpers;
    private final HextraCodeAreaPainter CodeAreaPainter;
    private CodeArea hexEditor;
    private DeltaHexPanel hexPanel;
    private IMessageEditor messageEditor;
    private ByteArrayEditableData data;

    public ViewStateTab(IBurpExtenderCallbacks callbacks, IMessageEditorController controller, boolean editable) {
        this.helpers = callbacks.getHelpers();
        this.messageEditor = callbacks.createMessageEditor(controller, editable);
        this.hexPanel = new DeltaHexPanel();
        hexEditor = new HexviewCodeArea();
        this.CodeAreaPainter = new HextraCodeAreaPainter(hexEditor);
        CodeAreaPainter.buildUnprintableCharactersMapping();
        this.data = new ByteArrayEditableData();
        hexEditor.setData(data);
        hexEditor.setPainter(CodeAreaPainter);
        this.hexPanel.setCodeArea(hexEditor);
    }

    @Override
    public String getTabCaption() {
        return "Hextraview";
    }

    @Override
    public Component getUiComponent() {
        return this.hexPanel.getComponent(0);
    }

    @Override
    public boolean isEnabled(byte[] content, boolean isRequest) {
        return true;
    }

    @Override
    public void setMessage(byte[] content, boolean isRequest) {
        this.data.setData(content);
        this.hexEditor.setData(this.data);
    }

    @Override
    public byte[] getMessage() {
        this.setMessage(this.data.getData(), true);
        return this.data.getData();
    }

    @Override
    public boolean isModified() {
        return true;
    }

    @Override
    public byte[] getSelectedData() {
        SelectionRange selected = this.hexEditor.getSelection();
        return Arrays.copyOfRange(this.data.getData(),(int)selected.getStart(),(int)selected.getEnd());
    }
}
