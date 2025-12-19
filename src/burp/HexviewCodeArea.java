package burp;

import org.exbin.bined.swing.basic.CodeArea;
import org.exbin.bined.swing.CodeAreaCommandHandler;
import org.exbin.bined.swing.CodeAreaCore;
import org.exbin.bined.operation.swing.CodeAreaOperationCommandHandler;
import org.exbin.bined.operation.swing.CodeAreaUndoRedo;
import org.exbin.bined.operation.undo.BinaryDataUndoRedo;

import javax.swing.*;
import java.awt.event.ActionEvent;
import java.awt.event.KeyEvent;

/**
 * Custom CodeArea with undo/redo support via Ctrl+Z and Ctrl+Y
 */
public class HexviewCodeArea extends CodeArea {

    private CodeAreaUndoRedo undoRedo;

    public HexviewCodeArea() {
        super(HexviewCodeArea::createCommandHandler);
        setupKeyBindings();
    }

    private static CodeAreaCommandHandler createCommandHandler(CodeAreaCore codeArea) {
        // Create undo/redo handler
        CodeAreaUndoRedo undoRedo = new CodeAreaUndoRedo(codeArea);

        // Store reference in the codeArea if it's our custom type
        if (codeArea instanceof HexviewCodeArea) {
            ((HexviewCodeArea) codeArea).undoRedo = undoRedo;
        }

        // Create operation command handler with undo/redo support
        return new CodeAreaOperationCommandHandler(codeArea, undoRedo);
    }

    private void setupKeyBindings() {
        // Undo: Ctrl+Z
        getInputMap(JComponent.WHEN_FOCUSED).put(
            KeyStroke.getKeyStroke(KeyEvent.VK_Z, KeyEvent.CTRL_DOWN_MASK), "undo");
        getActionMap().put("undo", new AbstractAction() {
            @Override
            public void actionPerformed(ActionEvent e) {
                performUndo();
            }
        });

        // Redo: Ctrl+Y
        getInputMap(JComponent.WHEN_FOCUSED).put(
            KeyStroke.getKeyStroke(KeyEvent.VK_Y, KeyEvent.CTRL_DOWN_MASK), "redo");
        getActionMap().put("redo", new AbstractAction() {
            @Override
            public void actionPerformed(ActionEvent e) {
                performRedo();
            }
        });

        // Redo: Ctrl+Shift+Z (alternative)
        getInputMap(JComponent.WHEN_FOCUSED).put(
            KeyStroke.getKeyStroke(KeyEvent.VK_Z, KeyEvent.CTRL_DOWN_MASK | KeyEvent.SHIFT_DOWN_MASK), "redo");
    }

    public void performUndo() {
        if (undoRedo != null && undoRedo.canUndo()) {
            undoRedo.performUndo();
            repaint();
        }
    }

    public void performRedo() {
        if (undoRedo != null && undoRedo.canRedo()) {
            undoRedo.performRedo();
            repaint();
        }
    }

    public boolean canUndo() {
        return undoRedo != null && undoRedo.canUndo();
    }

    public boolean canRedo() {
        return undoRedo != null && undoRedo.canRedo();
    }

    public BinaryDataUndoRedo getUndoRedo() {
        return undoRedo;
    }

    /**
     * Clear undo history (call when loading new data)
     */
    public void clearUndoHistory() {
        if (undoRedo != null) {
            undoRedo.clear();
        }
    }
}
