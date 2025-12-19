package burp;

import org.exbin.bined.highlight.swing.SearchCodeAreaColorAssessor;
import org.exbin.bined.highlight.swing.SearchMatch;
import org.exbin.bined.swing.basic.CodeArea;
import org.exbin.bined.swing.capability.ColorAssessorPainterCapable;
import org.exbin.bined.operation.swing.CodeAreaUndoRedo;
import org.exbin.bined.operation.swing.command.CodeAreaCompoundCommand;
import org.exbin.bined.operation.swing.command.InsertDataCommand;
import org.exbin.bined.operation.swing.command.RemoveDataCommand;
import org.exbin.auxiliary.binary_data.BinaryData;
import org.exbin.auxiliary.binary_data.EditableBinaryData;
import org.exbin.auxiliary.binary_data.array.ByteArrayData;

import javax.swing.*;
import java.awt.*;
import java.awt.event.*;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;

/**
 * Search and Replace panel for the hex editor
 */
public class SearchPanel extends JPanel {

    private final CodeArea codeArea;
    private final HextraCodeAreaPainter basePainter;
    private SearchCodeAreaColorAssessor searchAssessor;

    private JTextField searchField;
    private JTextField replaceField;
    private JComboBox<String> searchTypeCombo;
    private JCheckBox caseSensitiveCheck;
    private JCheckBox regexCheck;
    private JLabel statusLabel;
    private JButton prevButton;
    private JButton nextButton;
    private JButton replaceButton;
    private JButton replaceAllButton;
    private JPanel replacePanel;
    private boolean replaceVisible = false;

    private List<SearchMatch> matches = new ArrayList<>();
    private List<String> matchedStrings = new ArrayList<>();  // For regex capture groups
    private int currentMatchIndex = -1;
    private Pattern currentRegexPattern = null;  // Current compiled regex

    public SearchPanel(CodeArea codeArea, HextraCodeAreaPainter basePainter) {
        this.codeArea = codeArea;
        this.basePainter = basePainter;

        // Create search assessor wrapping the base painter
        this.searchAssessor = new SearchCodeAreaColorAssessor(basePainter);

        setLayout(new BorderLayout(5, 5));
        setBorder(BorderFactory.createEmptyBorder(5, 5, 5, 5));

        buildUI();
        setupKeyBindings();
    }

    private void buildUI() {
        // Search row
        JPanel searchRow = new JPanel(new FlowLayout(FlowLayout.LEFT, 5, 0));

        searchField = new JTextField(20);
        searchField.addActionListener(e -> findNext());
        searchField.getDocument().addDocumentListener(new javax.swing.event.DocumentListener() {
            public void insertUpdate(javax.swing.event.DocumentEvent e) { onSearchTextChanged(); }
            public void removeUpdate(javax.swing.event.DocumentEvent e) { onSearchTextChanged(); }
            public void changedUpdate(javax.swing.event.DocumentEvent e) { onSearchTextChanged(); }
        });

        searchTypeCombo = new JComboBox<>(new String[]{"Text", "Hex"});
        searchTypeCombo.addActionListener(e -> onSearchTypeChanged());

        caseSensitiveCheck = new JCheckBox("Case");
        caseSensitiveCheck.addActionListener(e -> onSearchTextChanged());

        regexCheck = new JCheckBox("Regex");
        regexCheck.setToolTipText("Use regular expressions (Text mode only)");
        regexCheck.addActionListener(e -> onSearchTextChanged());

        prevButton = new JButton("◀");
        prevButton.setToolTipText("Previous (Shift+F3)");
        prevButton.addActionListener(e -> findPrevious());

        nextButton = new JButton("▶");
        nextButton.setToolTipText("Next (F3)");
        nextButton.addActionListener(e -> findNext());

        JButton toggleReplaceButton = new JButton("Replace");
        toggleReplaceButton.addActionListener(e -> toggleReplace());

        JButton closeButton = new JButton("✕");
        closeButton.setToolTipText("Close (Esc)");
        closeButton.addActionListener(e -> closePanel());

        statusLabel = new JLabel("");

        searchRow.add(new JLabel("Find:"));
        searchRow.add(searchField);
        searchRow.add(searchTypeCombo);
        searchRow.add(caseSensitiveCheck);
        searchRow.add(regexCheck);
        searchRow.add(prevButton);
        searchRow.add(nextButton);
        searchRow.add(toggleReplaceButton);
        searchRow.add(statusLabel);
        searchRow.add(Box.createHorizontalGlue());
        searchRow.add(closeButton);

        // Replace row (initially hidden)
        replacePanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 5, 0));
        replaceField = new JTextField(20);
        replaceField.addActionListener(e -> replaceCurrent());

        replaceButton = new JButton("Replace");
        replaceButton.addActionListener(e -> replaceCurrent());

        replaceAllButton = new JButton("Replace All");
        replaceAllButton.addActionListener(e -> replaceAll());

        replacePanel.add(new JLabel("Replace:"));
        replacePanel.add(replaceField);
        replacePanel.add(replaceButton);
        replacePanel.add(replaceAllButton);
        replacePanel.setVisible(false);

        JPanel mainPanel = new JPanel();
        mainPanel.setLayout(new BoxLayout(mainPanel, BoxLayout.Y_AXIS));
        mainPanel.add(searchRow);
        mainPanel.add(replacePanel);

        add(mainPanel, BorderLayout.CENTER);
    }

    private void setupKeyBindings() {
        // Escape to close
        getInputMap(JComponent.WHEN_ANCESTOR_OF_FOCUSED_COMPONENT).put(
            KeyStroke.getKeyStroke(KeyEvent.VK_ESCAPE, 0), "close");
        getActionMap().put("close", new AbstractAction() {
            @Override
            public void actionPerformed(ActionEvent e) {
                closePanel();
            }
        });

        // F3 for next
        getInputMap(JComponent.WHEN_ANCESTOR_OF_FOCUSED_COMPONENT).put(
            KeyStroke.getKeyStroke(KeyEvent.VK_F3, 0), "findNext");
        getActionMap().put("findNext", new AbstractAction() {
            @Override
            public void actionPerformed(ActionEvent e) {
                findNext();
            }
        });

        // Shift+F3 for previous
        getInputMap(JComponent.WHEN_ANCESTOR_OF_FOCUSED_COMPONENT).put(
            KeyStroke.getKeyStroke(KeyEvent.VK_F3, KeyEvent.SHIFT_DOWN_MASK), "findPrev");
        getActionMap().put("findPrev", new AbstractAction() {
            @Override
            public void actionPerformed(ActionEvent e) {
                findPrevious();
            }
        });

        // Enter in search field finds next
        searchField.getInputMap().put(KeyStroke.getKeyStroke(KeyEvent.VK_ENTER, 0), "findNext");
        searchField.getActionMap().put("findNext", new AbstractAction() {
            @Override
            public void actionPerformed(ActionEvent e) {
                findNext();
            }
        });
    }

    private void toggleReplace() {
        replaceVisible = !replaceVisible;
        replacePanel.setVisible(replaceVisible);
        revalidate();
    }

    private void onSearchTextChanged() {
        performSearch();
    }

    private void onSearchTypeChanged() {
        // Disable regex checkbox when Hex mode is selected
        boolean isHexMode = "Hex".equals(searchTypeCombo.getSelectedItem());
        regexCheck.setEnabled(!isHexMode);
        if (isHexMode) {
            regexCheck.setSelected(false);
        }
        performSearch();
    }

    private void performSearch() {
        String searchText = searchField.getText();
        matches.clear();
        matchedStrings.clear();
        currentMatchIndex = -1;
        currentRegexPattern = null;

        if (searchText.isEmpty()) {
            updateSearchAssessor();
            updateStatus();
            return;
        }

        BinaryData data = codeArea.getContentData();
        if (data == null || data.getDataSize() == 0) {
            updateSearchAssessor();
            updateStatus();
            return;
        }

        boolean isHexSearch = "Hex".equals(searchTypeCombo.getSelectedItem());
        boolean isRegexSearch = regexCheck.isSelected() && !isHexSearch;

        if (isRegexSearch) {
            // Regex search
            performRegexSearch(data, searchText);
        } else if (isHexSearch) {
            // Hex search
            byte[] searchBytes = parseHexString(searchText);
            if (searchBytes == null) {
                statusLabel.setText("Invalid hex");
                statusLabel.setForeground(Color.RED);
                updateSearchAssessor();
                return;
            }
            performBytesSearch(data, searchBytes, false);
        } else {
            // Text search
            byte[] searchBytes;
            if (!caseSensitiveCheck.isSelected()) {
                searchBytes = searchText.toLowerCase().getBytes();
            } else {
                searchBytes = searchText.getBytes();
            }
            performBytesSearch(data, searchBytes, !caseSensitiveCheck.isSelected());
        }

        if (!matches.isEmpty()) {
            currentMatchIndex = 0;
            goToMatch(0);
        }

        updateSearchAssessor();
        updateStatus();
    }

    private void performBytesSearch(BinaryData data, byte[] searchBytes, boolean caseInsensitive) {
        if (searchBytes.length == 0) {
            return;
        }

        long dataSize = data.getDataSize();
        for (long i = 0; i <= dataSize - searchBytes.length; i++) {
            boolean found = true;
            for (int j = 0; j < searchBytes.length; j++) {
                byte dataByte = data.getByte(i + j);
                byte searchByte = searchBytes[j];

                if (caseInsensitive) {
                    dataByte = (byte) Character.toLowerCase((char) (dataByte & 0xFF));
                }

                if (dataByte != searchByte) {
                    found = false;
                    break;
                }
            }
            if (found) {
                matches.add(new SearchMatch(i, searchBytes.length));
                matchedStrings.add(null);  // No matched string for byte search
            }
        }
    }

    private void performRegexSearch(BinaryData data, String regexPattern) {
        // Convert binary data to string for regex matching
        long dataSize = data.getDataSize();
        if (dataSize > 10 * 1024 * 1024) {  // Limit to 10MB for regex
            statusLabel.setText("Data too large for regex");
            statusLabel.setForeground(Color.RED);
            return;
        }

        // Build string from binary data
        byte[] bytes = new byte[(int) dataSize];
        for (int i = 0; i < dataSize; i++) {
            bytes[i] = data.getByte(i);
        }
        String text = new String(bytes);

        // Compile regex pattern
        try {
            int flags = caseSensitiveCheck.isSelected() ? 0 : Pattern.CASE_INSENSITIVE;
            currentRegexPattern = Pattern.compile(regexPattern, flags);
        } catch (PatternSyntaxException e) {
            statusLabel.setText("Invalid regex: " + e.getDescription());
            statusLabel.setForeground(Color.RED);
            return;
        }

        // Find all matches
        Matcher matcher = currentRegexPattern.matcher(text);
        while (matcher.find()) {
            int start = matcher.start();
            int length = matcher.end() - start;
            if (length > 0) {
                matches.add(new SearchMatch(start, length));
                matchedStrings.add(matcher.group());  // Store matched text for replacement
            }
        }
    }

    private byte[] parseHexString(String hex) {
        // Remove spaces and common separators
        hex = hex.replaceAll("[\\s,:-]", "");

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

    private void updateSearchAssessor() {
        searchAssessor.setMatches(matches);
        if (currentMatchIndex >= 0 && currentMatchIndex < matches.size()) {
            searchAssessor.setCurrentMatchIndex(currentMatchIndex);
        }

        // Apply search assessor
        if (codeArea.getPainter() instanceof ColorAssessorPainterCapable) {
            ((ColorAssessorPainterCapable) codeArea.getPainter()).setColorAssessor(searchAssessor);
        }
        codeArea.repaint();
    }

    private void updateStatus() {
        if (matches.isEmpty()) {
            if (searchField.getText().isEmpty()) {
                statusLabel.setText("");
            } else {
                statusLabel.setText("No matches");
                statusLabel.setForeground(Color.RED);
            }
        } else {
            statusLabel.setText((currentMatchIndex + 1) + "/" + matches.size());
            statusLabel.setForeground(Color.BLACK);
        }
    }

    private void goToMatch(int index) {
        if (index >= 0 && index < matches.size()) {
            currentMatchIndex = index;
            SearchMatch match = matches.get(index);
            codeArea.setActiveCaretPosition(match.getPosition());
            codeArea.revealCursor();
            searchAssessor.setCurrentMatchIndex(index);
            codeArea.repaint();
            updateStatus();
        }
    }

    public void findNext() {
        if (matches.isEmpty()) {
            performSearch();
            return;
        }
        int next = (currentMatchIndex + 1) % matches.size();
        goToMatch(next);
    }

    public void findPrevious() {
        if (matches.isEmpty()) {
            performSearch();
            return;
        }
        int prev = (currentMatchIndex - 1 + matches.size()) % matches.size();
        goToMatch(prev);
    }

    private void replaceCurrent() {
        if (currentMatchIndex < 0 || currentMatchIndex >= matches.size()) {
            return;
        }

        byte[] replaceBytes = getReplaceBytesForMatch(currentMatchIndex);
        if (replaceBytes == null) {
            return;
        }

        SearchMatch match = matches.get(currentMatchIndex);
        replaceAt(match.getPosition(), (int) match.getLength(), replaceBytes);

        // Re-search after replacement
        performSearch();
    }

    private void replaceAll() {
        if (matches.isEmpty()) {
            return;
        }

        // Pre-compute all replacement bytes (needed for regex with varying capture groups)
        List<byte[]> allReplacements = new ArrayList<>();
        for (int i = 0; i < matches.size(); i++) {
            byte[] replaceBytes = getReplaceBytesForMatch(i);
            if (replaceBytes == null) {
                return;  // Error occurred
            }
            allReplacements.add(replaceBytes);
        }

        int count = matches.size();

        // Use undo/redo system if available - all replacements as one command
        if (codeArea instanceof HexviewCodeArea) {
            HexviewCodeArea hexCodeArea = (HexviewCodeArea) codeArea;
            CodeAreaUndoRedo undoRedo = (CodeAreaUndoRedo) hexCodeArea.getUndoRedo();

            if (undoRedo != null) {
                // Create a single compound command for all replacements
                CodeAreaCompoundCommand compoundCommand = new CodeAreaCompoundCommand(codeArea);

                // Replace from end to start to preserve positions
                for (int i = matches.size() - 1; i >= 0; i--) {
                    SearchMatch match = matches.get(i);
                    long position = match.getPosition();
                    int length = (int) match.getLength();
                    byte[] replaceBytes = allReplacements.get(i);

                    // Add remove command
                    if (length > 0) {
                        RemoveDataCommand removeCmd = new RemoveDataCommand(codeArea, position, 0, length);
                        compoundCommand.addCommand(removeCmd);
                    }

                    // Add insert command
                    if (replaceBytes.length > 0) {
                        ByteArrayData insertData = new ByteArrayData(replaceBytes);
                        InsertDataCommand insertCmd = new InsertDataCommand(codeArea, position, 0, insertData);
                        compoundCommand.addCommand(insertCmd);
                    }
                }

                // Execute all as one undoable operation
                undoRedo.execute(compoundCommand);
                codeArea.repaint();
                performSearch();
                statusLabel.setText("Replaced " + count);
                return;
            }
        }

        // Fallback: individual replacements (no undo support)
        for (int i = matches.size() - 1; i >= 0; i--) {
            SearchMatch match = matches.get(i);
            byte[] replaceBytes = allReplacements.get(i);
            replaceAt(match.getPosition(), (int) match.getLength(), replaceBytes);
        }

        performSearch();
        statusLabel.setText("Replaced " + count);
    }

    /**
     * Get replacement bytes for a specific match index.
     * For regex mode, applies capture group substitution ($1, $2, etc.)
     */
    private byte[] getReplaceBytesForMatch(int matchIndex) {
        String replaceText = replaceField.getText();
        boolean isHexSearch = "Hex".equals(searchTypeCombo.getSelectedItem());
        boolean isRegexSearch = regexCheck.isSelected() && !isHexSearch;

        if (isHexSearch) {
            byte[] bytes = parseHexString(replaceText);
            if (bytes == null && !replaceText.isEmpty()) {
                statusLabel.setText("Invalid hex");
                statusLabel.setForeground(Color.RED);
                return null;
            }
            return bytes != null ? bytes : new byte[0];
        } else if (isRegexSearch && currentRegexPattern != null) {
            // Apply regex replacement with capture groups
            String matchedText = matchedStrings.get(matchIndex);
            if (matchedText != null) {
                try {
                    Matcher matcher = currentRegexPattern.matcher(matchedText);
                    if (matcher.matches()) {
                        // Apply replacement pattern (supports $1, $2, etc.)
                        String replaced = matcher.replaceFirst(replaceText);
                        return replaced.getBytes();
                    }
                } catch (Exception e) {
                    statusLabel.setText("Replace error: " + e.getMessage());
                    statusLabel.setForeground(Color.RED);
                    return null;
                }
            }
            return replaceText.getBytes();
        } else {
            // Plain text replacement
            return replaceText.getBytes();
        }
    }

    private void replaceAt(long position, int length, byte[] replacement) {
        // Use undo/redo system if available (HexviewCodeArea)
        if (codeArea instanceof HexviewCodeArea) {
            HexviewCodeArea hexCodeArea = (HexviewCodeArea) codeArea;
            CodeAreaUndoRedo undoRedo = (CodeAreaUndoRedo) hexCodeArea.getUndoRedo();

            if (undoRedo != null) {
                // Create a compound command for the replace operation
                CodeAreaCompoundCommand compoundCommand = new CodeAreaCompoundCommand(codeArea);

                // First remove the old data
                if (length > 0) {
                    RemoveDataCommand removeCmd = new RemoveDataCommand(codeArea, position, 0, length);
                    compoundCommand.addCommand(removeCmd);
                }

                // Then insert the new data
                if (replacement.length > 0) {
                    ByteArrayData insertData = new ByteArrayData(replacement);
                    InsertDataCommand insertCmd = new InsertDataCommand(codeArea, position, 0, insertData);
                    compoundCommand.addCommand(insertCmd);
                }

                // Execute through undo/redo system
                undoRedo.execute(compoundCommand);
                codeArea.repaint();
                return;
            }
        }

        // Fallback: direct modification (no undo support)
        BinaryData data = codeArea.getContentData();
        if (data instanceof EditableBinaryData) {
            EditableBinaryData editableData = (EditableBinaryData) data;

            // Remove old bytes
            editableData.remove(position, length);

            // Insert new bytes
            if (replacement.length > 0) {
                editableData.insert(position, replacement);
            }

            codeArea.notifyDataChanged();
            codeArea.repaint();
        }
    }

    public void closePanel() {
        // Clear highlights
        matches.clear();
        searchAssessor.clearMatches();

        // Restore base painter
        if (codeArea.getPainter() instanceof ColorAssessorPainterCapable) {
            ((ColorAssessorPainterCapable) codeArea.getPainter()).setColorAssessor(basePainter);
        }
        codeArea.repaint();

        setVisible(false);
    }

    public void showPanel() {
        setVisible(true);
        searchField.requestFocusInWindow();
        searchField.selectAll();
    }

    public void focusSearch() {
        searchField.requestFocusInWindow();
        searchField.selectAll();
    }
}
