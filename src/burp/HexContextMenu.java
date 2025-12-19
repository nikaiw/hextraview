package burp;

import org.exbin.bined.SelectionRange;
import org.exbin.bined.swing.basic.CodeArea;
import org.exbin.bined.operation.swing.CodeAreaUndoRedo;
import org.exbin.bined.operation.swing.command.CodeAreaCompoundCommand;
import org.exbin.bined.operation.swing.command.InsertDataCommand;
import org.exbin.bined.operation.swing.command.RemoveDataCommand;
import org.exbin.auxiliary.binary_data.BinaryData;
import org.exbin.auxiliary.binary_data.EditableBinaryData;
import org.exbin.auxiliary.binary_data.array.ByteArrayData;

import javax.swing.*;
import javax.swing.SwingUtilities;
import java.awt.*;
import java.awt.datatransfer.*;
import java.awt.event.ActionEvent;
import java.awt.event.KeyEvent;
import java.util.Base64;

/**
 * Context menu for the hex editor with copy, paste, and navigation actions.
 */
public class HexContextMenu extends JPopupMenu {

    private final CodeArea codeArea;
    private final HttpRegionParser regionParser;

    // Menu items
    private JMenuItem copyItem;
    private JMenuItem copyHexItem;
    private JMenuItem copyCArrayItem;
    private JMenuItem copyBase64Item;
    private JMenuItem pasteItem;
    private JMenuItem pasteInBodyItem;
    private JMenuItem pasteHexItem;
    private JMenuItem pasteBase64Item;
    private JMenuItem selectAllItem;
    private JMenuItem goToOffsetItem;

    public HexContextMenu(CodeArea codeArea, HttpRegionParser regionParser) {
        this.codeArea = codeArea;
        this.regionParser = regionParser;

        buildMenu();
    }

    /**
     * Get the parent frame for dialogs (required by BApp Store criteria)
     */
    private Frame getParentFrame() {
        Window window = SwingUtilities.getWindowAncestor(codeArea);
        if (window instanceof Frame) {
            return (Frame) window;
        }
        return null;
    }

    private void buildMenu() {
        // Copy actions
        copyItem = new JMenuItem("Copy");
        copyItem.setAccelerator(KeyStroke.getKeyStroke(KeyEvent.VK_C, KeyEvent.CTRL_DOWN_MASK));
        copyItem.addActionListener(e -> copyAsText());
        add(copyItem);

        copyHexItem = new JMenuItem("Copy as Hex");
        copyHexItem.addActionListener(e -> copyAsHex());
        add(copyHexItem);

        copyCArrayItem = new JMenuItem("Copy as C Array");
        copyCArrayItem.addActionListener(e -> copyAsCArray());
        add(copyCArrayItem);

        copyBase64Item = new JMenuItem("Copy as Base64");
        copyBase64Item.addActionListener(e -> copyAsBase64());
        add(copyBase64Item);

        addSeparator();

        // Paste actions
        pasteItem = new JMenuItem("Paste");
        pasteItem.setAccelerator(KeyStroke.getKeyStroke(KeyEvent.VK_V, KeyEvent.CTRL_DOWN_MASK));
        pasteItem.addActionListener(e -> pasteText());
        add(pasteItem);

        pasteInBodyItem = new JMenuItem("Paste in Body");
        pasteInBodyItem.addActionListener(e -> pasteInBody());
        add(pasteInBodyItem);

        pasteHexItem = new JMenuItem("Paste as Hex");
        pasteHexItem.addActionListener(e -> pasteAsHex());
        add(pasteHexItem);

        pasteBase64Item = new JMenuItem("Paste from Base64");
        pasteBase64Item.addActionListener(e -> pasteFromBase64());
        add(pasteBase64Item);

        addSeparator();

        // Other actions
        selectAllItem = new JMenuItem("Select All");
        selectAllItem.setAccelerator(KeyStroke.getKeyStroke(KeyEvent.VK_A, KeyEvent.CTRL_DOWN_MASK));
        selectAllItem.addActionListener(e -> selectAll());
        add(selectAllItem);

        goToOffsetItem = new JMenuItem("Go to Offset...");
        goToOffsetItem.setAccelerator(KeyStroke.getKeyStroke(KeyEvent.VK_G, KeyEvent.CTRL_DOWN_MASK));
        goToOffsetItem.addActionListener(e -> goToOffset());
        add(goToOffsetItem);
    }

    /**
     * Update menu items state before showing (enable/disable based on selection)
     */
    public void updateMenuState() {
        boolean hasSelection = hasSelection();
        boolean hasClipboard = hasClipboardText();
        boolean hasBody = regionParser != null && regionParser.hasBody();
        long caretPosition = codeArea.getActiveCaretPosition().getDataPosition();
        boolean inBody = hasBody && caretPosition >= regionParser.getBodyStart();

        // Copy items need selection
        copyItem.setEnabled(hasSelection);
        copyHexItem.setEnabled(hasSelection);
        copyCArrayItem.setEnabled(hasSelection);
        copyBase64Item.setEnabled(hasSelection);

        // Paste items need clipboard content
        pasteItem.setEnabled(hasClipboard);
        pasteInBodyItem.setEnabled(hasClipboard && hasBody);
        pasteHexItem.setEnabled(hasClipboard);
        pasteBase64Item.setEnabled(hasClipboard);

        // Other items always enabled
        selectAllItem.setEnabled(codeArea.getDataSize() > 0);
        goToOffsetItem.setEnabled(codeArea.getDataSize() > 0);
    }

    private boolean hasSelection() {
        SelectionRange selection = codeArea.getSelection();
        return selection != null && !selection.isEmpty();
    }

    private boolean hasClipboardText() {
        try {
            Clipboard clipboard = Toolkit.getDefaultToolkit().getSystemClipboard();
            return clipboard.isDataFlavorAvailable(DataFlavor.stringFlavor);
        } catch (Exception e) {
            return false;
        }
    }

    // ========== Get Selected Bytes ==========

    private byte[] getSelectedBytes() {
        SelectionRange selection = codeArea.getSelection();
        if (selection == null || selection.isEmpty()) {
            return new byte[0];
        }

        long start = selection.getFirst();
        long end = selection.getLast() + 1;
        int length = (int) (end - start);
        byte[] bytes = new byte[length];
        BinaryData data = codeArea.getContentData();

        for (int i = 0; i < length; i++) {
            bytes[i] = data.getByte(start + i);
        }
        return bytes;
    }

    // ========== Copy Operations ==========

    private void copyAsText() {
        byte[] bytes = getSelectedBytes();
        if (bytes.length == 0) return;
        copyToClipboard(new String(bytes));
    }

    private void copyAsHex() {
        byte[] bytes = getSelectedBytes();
        if (bytes.length == 0) return;
        copyToClipboard(toHexString(bytes));
    }

    private void copyAsCArray() {
        byte[] bytes = getSelectedBytes();
        if (bytes.length == 0) return;
        copyToClipboard(toCArrayString(bytes));
    }

    private void copyAsBase64() {
        byte[] bytes = getSelectedBytes();
        if (bytes.length == 0) return;
        copyToClipboard(Base64.getEncoder().encodeToString(bytes));
    }

    private void copyToClipboard(String text) {
        StringSelection selection = new StringSelection(text);
        Toolkit.getDefaultToolkit().getSystemClipboard().setContents(selection, selection);
    }

    // ========== Format Conversions ==========

    private String toHexString(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < bytes.length; i++) {
            if (i > 0) sb.append(' ');
            sb.append(String.format("%02X", bytes[i] & 0xFF));
        }
        return sb.toString();
    }

    private String toCArrayString(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("\\x%02X", b & 0xFF));
        }
        return sb.toString();
    }

    // ========== Paste Operations ==========

    private String getClipboardText() {
        try {
            Clipboard clipboard = Toolkit.getDefaultToolkit().getSystemClipboard();
            return (String) clipboard.getData(DataFlavor.stringFlavor);
        } catch (Exception e) {
            return null;
        }
    }

    private void pasteText() {
        String text = getClipboardText();
        if (text == null) return;
        insertBytes(text.getBytes());
    }

    private void pasteInBody() {
        if (regionParser == null || !regionParser.hasBody()) {
            JOptionPane.showMessageDialog(getParentFrame(),
                "No HTTP body detected in current data.",
                "Paste in Body", JOptionPane.WARNING_MESSAGE);
            return;
        }

        String text = getClipboardText();
        if (text == null) return;

        // Move cursor to body start if not already there
        long caretPosition = codeArea.getActiveCaretPosition().getDataPosition();
        int bodyStart = regionParser.getBodyStart();

        if (caretPosition < bodyStart) {
            codeArea.setActiveCaretPosition(bodyStart);
        }

        insertBytes(text.getBytes());
    }

    private void pasteAsHex() {
        String text = getClipboardText();
        if (text == null) return;

        byte[] bytes = parseHexString(text);
        if (bytes == null) {
            JOptionPane.showMessageDialog(getParentFrame(),
                "Invalid hex format in clipboard.",
                "Paste as Hex", JOptionPane.ERROR_MESSAGE);
            return;
        }
        insertBytes(bytes);
    }

    private void pasteFromBase64() {
        String text = getClipboardText();
        if (text == null) return;

        try {
            byte[] bytes = Base64.getDecoder().decode(text.trim());
            insertBytes(bytes);
        } catch (IllegalArgumentException e) {
            JOptionPane.showMessageDialog(getParentFrame(),
                "Invalid Base64 format in clipboard.",
                "Paste from Base64", JOptionPane.ERROR_MESSAGE);
        }
    }

    private byte[] parseHexString(String hex) {
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

    private void insertBytes(byte[] bytes) {
        if (bytes.length == 0) return;

        long position = codeArea.getActiveCaretPosition().getDataPosition();

        // Use undo/redo system if available
        if (codeArea instanceof HexviewCodeArea) {
            HexviewCodeArea hexCodeArea = (HexviewCodeArea) codeArea;
            CodeAreaUndoRedo undoRedo = (CodeAreaUndoRedo) hexCodeArea.getUndoRedo();

            if (undoRedo != null) {
                // Check if there's a selection to replace
                SelectionRange selection = codeArea.getSelection();
                CodeAreaCompoundCommand compoundCommand = new CodeAreaCompoundCommand(codeArea);

                if (selection != null && !selection.isEmpty()) {
                    // Remove selected data first
                    long start = selection.getFirst();
                    int length = (int) (selection.getLast() - start + 1);
                    RemoveDataCommand removeCmd = new RemoveDataCommand(codeArea, start, 0, length);
                    compoundCommand.addCommand(removeCmd);
                    position = start;
                }

                // Insert new data
                ByteArrayData insertData = new ByteArrayData(bytes);
                InsertDataCommand insertCmd = new InsertDataCommand(codeArea, position, 0, insertData);
                compoundCommand.addCommand(insertCmd);

                undoRedo.execute(compoundCommand);
                codeArea.repaint();
                return;
            }
        }

        // Fallback: direct modification
        BinaryData data = codeArea.getContentData();
        if (data instanceof EditableBinaryData) {
            EditableBinaryData editableData = (EditableBinaryData) data;

            // Remove selection if any
            SelectionRange selection = codeArea.getSelection();
            if (selection != null && !selection.isEmpty()) {
                long start = selection.getFirst();
                int length = (int) (selection.getLast() - start + 1);
                editableData.remove(start, length);
                position = start;
            }

            // Insert new data
            editableData.insert(position, bytes);
            codeArea.notifyDataChanged();
            codeArea.repaint();
        }
    }

    // ========== Other Actions ==========

    private void selectAll() {
        long dataSize = codeArea.getDataSize();
        if (dataSize > 0) {
            codeArea.setSelection(0, dataSize);
            codeArea.repaint();
        }
    }

    public void goToOffset() {
        String input = JOptionPane.showInputDialog(getParentFrame(),
            "Enter offset (hex with 0x prefix, or decimal):",
            "Go to Offset", JOptionPane.PLAIN_MESSAGE);

        if (input == null || input.trim().isEmpty()) {
            return;
        }

        try {
            long offset;
            input = input.trim();

            if (input.toLowerCase().startsWith("0x")) {
                // Hex format
                offset = Long.parseLong(input.substring(2), 16);
            } else {
                // Decimal format
                offset = Long.parseLong(input);
            }

            long dataSize = codeArea.getDataSize();
            if (offset < 0 || offset >= dataSize) {
                JOptionPane.showMessageDialog(getParentFrame(),
                    "Offset out of range. Valid range: 0 to " + (dataSize - 1),
                    "Go to Offset", JOptionPane.ERROR_MESSAGE);
                return;
            }

            codeArea.setActiveCaretPosition(offset);
            codeArea.revealCursor();
            codeArea.repaint();

        } catch (NumberFormatException e) {
            JOptionPane.showMessageDialog(getParentFrame(),
                "Invalid offset format. Use decimal or 0x prefix for hex.",
                "Go to Offset", JOptionPane.ERROR_MESSAGE);
        }
    }
}
