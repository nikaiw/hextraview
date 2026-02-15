/*
 * Copyright (C) ExBin Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package burp;

import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.Component;
import java.awt.Dimension;
import java.awt.FlowLayout;
import java.awt.Font;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Insets;
import java.awt.Frame;
import java.awt.Window;
import java.awt.event.ActionEvent;
import java.awt.event.KeyEvent;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.charset.Charset;
import java.util.HashMap;
import java.util.Map;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.swing.AbstractAction;
import javax.swing.BorderFactory;
import javax.swing.Box;
import javax.swing.BoxLayout;
import javax.swing.JButton;
import javax.swing.JComponent;
import javax.swing.KeyStroke;
import javax.swing.JColorChooser;
import javax.swing.JFileChooser;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTextArea;
import javax.swing.SwingUtilities;
import javax.swing.border.BevelBorder;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;
import java.nio.charset.StandardCharsets;
import org.exbin.auxiliary.binary_data.array.ByteArrayEditableData;
import javax.swing.border.Border;
import javax.swing.border.EmptyBorder;
import javax.swing.border.EtchedBorder;
import javax.swing.border.LineBorder;
import javax.swing.filechooser.FileFilter;
import javax.swing.plaf.basic.BasicBorders;
import org.exbin.bined.CodeAreaCaretPosition;
import org.exbin.bined.CodeAreaCaretListener;
import org.exbin.bined.CodeType;
import org.exbin.bined.DataChangedListener;
import org.exbin.bined.EditMode;
import org.exbin.bined.CodeCharactersCase;
import org.exbin.bined.PositionCodeType;
import org.exbin.bined.ScrollBarVisibility;
import org.exbin.bined.CodeAreaSection;
import org.exbin.bined.SelectionChangedListener;
import org.exbin.bined.SelectionRange;
import org.exbin.bined.basic.CodeAreaViewMode;
import org.exbin.bined.basic.BasicBackgroundPaintMode;
import org.exbin.bined.RowWrappingMode;
import org.exbin.bined.EditOperation;
import org.exbin.bined.swing.basic.AntialiasingMode;
import org.exbin.bined.swing.basic.CodeArea;
import org.exbin.bined.CodeAreaCaret;
import org.exbin.auxiliary.binary_data.EditableBinaryData;

/**
 * Hexadecimal editor example panel.
 *
 * @version 0.1.3 2017/03/02
 * @author ExBin Project (http://exbin.org)
 */
public class DeltaHexPanel extends javax.swing.JPanel {

    private static final int MIN_SETTINGS_PANEL_WIDTH_PX = 260;
    private static final int DEFAULT_SETTINGS_PANEL_WIDTH_PX = 280;

    private CodeArea codeArea;
    private final Map<JPanel, JPanel> tabMap = new HashMap<>();
    private JPanel activeTab;

    // Settings manager for persistence
    private SettingsManager settingsManager;

    // Custom painter reference
    private HextraCodeAreaPainter hextraPainter;

    // Color picker buttons - text colors
    private JButton printableColorButton;
    private JButton nullByteColorButton;
    private JButton unprintableColorButton;
    private JButton spaceColorButton;

    // Character background color buttons and checkboxes
    private JButton printableBgButton;
    private JButton nullByteBgButton;
    private JButton unprintableBgButton;
    private JButton spaceBgButton;
    private javax.swing.JCheckBox printableBgCheckBox;
    private javax.swing.JCheckBox nullByteBgCheckBox;
    private javax.swing.JCheckBox unprintableBgCheckBox;
    private javax.swing.JCheckBox spaceBgCheckBox;

    // Region background color buttons (HTTP)
    private JButton requestLineBgButton;
    private JButton headersBgButton;
    private JButton bodyBgButton;
    private JButton defaultBgButton;
    private javax.swing.JCheckBox regionColoringCheckBox;

    // WebSocket mode
    private boolean webSocketMode = false;

    // WebSocket region color buttons
    private JButton wsKeyBgButton;
    private JButton wsStringBgButton;
    private JButton wsNumberBgButton;
    private JButton wsStructureBgButton;
    private JButton wsLiteralBgButton;
    private JButton wsBinaryBgButton;
    private JButton wsDefaultBgButton;

    // Colors tab
    private JPanel colorsTab;
    private JPanel colorsPanel;

    // Raw tab for bidirectional sync
    private JPanel rawTab;
    private JTextArea rawTextArea;
    private boolean syncInProgress = false;

    // Collapsible settings panel
    private boolean settingsCollapsed = false;
    private int lastDividerLocation = 200;
    private JButton toggleSettingsButton;
    private JLabel expandSettingsLink;
    private JPanel hexAreaWrapper;
    private JPanel settingsWrapperPanel;

    // Options tab
    private JPanel optionsTab;
    private JPanel optionsPanel;

    // Theme selector
    private javax.swing.JComboBox<String> themeComboBox;
    private boolean suppressThemeComboEvents = false;

    // Search panel
    private SearchPanel searchPanel;

    // Context menu
    private HexContextMenu contextMenu;

    public DeltaHexPanel() {
        initComponents();
    }

    public void setCodeArea(final CodeArea codeArea) {
        this.codeArea = codeArea;

        // Add simple right-click test listener directly here
        codeArea.addMouseListener(new java.awt.event.MouseAdapter() {
            @Override
            public void mouseClicked(java.awt.event.MouseEvent e) {
                if (javax.swing.SwingUtilities.isRightMouseButton(e)) {
                    // If context menu is initialized, show it
                    if (contextMenu != null) {
                        contextMenu.updateMenuState();
                        contextMenu.show(codeArea, e.getX(), e.getY());
                    }
                }
            }
        });

        // Create wrapper for hex area with expand link
        hexAreaWrapper = new JPanel(new BorderLayout());

        // Create expand settings link (shown when settings are collapsed)
        expandSettingsLink = new JLabel("[show settings]");
        expandSettingsLink.setForeground(Color.GRAY);
        expandSettingsLink.setFont(expandSettingsLink.getFont().deriveFont(Font.PLAIN, 10f));
        expandSettingsLink.setCursor(new java.awt.Cursor(java.awt.Cursor.HAND_CURSOR));
        expandSettingsLink.setBorder(BorderFactory.createEmptyBorder(2, 5, 2, 5));
        expandSettingsLink.setVisible(false);
        expandSettingsLink.addMouseListener(new java.awt.event.MouseAdapter() {
            @Override
            public void mouseClicked(java.awt.event.MouseEvent e) {
                toggleSettingsPanel();
            }
            @Override
            public void mouseEntered(java.awt.event.MouseEvent e) {
                expandSettingsLink.setForeground(Color.BLUE);
            }
            @Override
            public void mouseExited(java.awt.event.MouseEvent e) {
                expandSettingsLink.setForeground(Color.GRAY);
            }
        });

        // Create toolbar with search button and settings link
        JPanel toolbarPanel = new JPanel(new BorderLayout());

        // Left side: settings link
        toolbarPanel.add(expandSettingsLink, BorderLayout.WEST);

        // Right side: search button
        JButton searchButton = new JButton("Search");
        searchButton.setFont(searchButton.getFont().deriveFont(Font.PLAIN, 10f));
        searchButton.setMargin(new Insets(2, 8, 2, 8));
        searchButton.setToolTipText("Search (Ctrl+Shift+F)");
        searchButton.addActionListener(e -> showSearchPanel());
        JPanel buttonPanel = new JPanel(new FlowLayout(FlowLayout.RIGHT, 5, 0));
        buttonPanel.add(searchButton);
        toolbarPanel.add(buttonPanel, BorderLayout.EAST);

        // Add Ctrl+Shift+F keyboard shortcut to open search panel
        codeArea.getInputMap(JComponent.WHEN_ANCESTOR_OF_FOCUSED_COMPONENT).put(
            KeyStroke.getKeyStroke(KeyEvent.VK_F, KeyEvent.CTRL_DOWN_MASK | KeyEvent.SHIFT_DOWN_MASK), "openSearch");
        codeArea.getActionMap().put("openSearch", new AbstractAction() {
            @Override
            public void actionPerformed(ActionEvent e) {
                showSearchPanel();
            }
        });

        // Add Ctrl+G keyboard shortcut for Go to Offset
        codeArea.getInputMap(JComponent.WHEN_ANCESTOR_OF_FOCUSED_COMPONENT).put(
            KeyStroke.getKeyStroke(KeyEvent.VK_G, KeyEvent.CTRL_DOWN_MASK), "goToOffset");
        codeArea.getActionMap().put("goToOffset", new AbstractAction() {
            @Override
            public void actionPerformed(ActionEvent e) {
                if (contextMenu != null) {
                    contextMenu.goToOffset();
                }
            }
        });

        // Create top panel with toolbar (search panel will be added below)
        JPanel topPanel = new JPanel(new BorderLayout());
        topPanel.add(toolbarPanel, BorderLayout.NORTH);

        hexAreaWrapper.add(topPanel, BorderLayout.NORTH);
        hexAreaWrapper.add(codeArea, BorderLayout.CENTER);

        // Set wrapper as right component
        splitPane.setRightComponent(hexAreaWrapper);

        // Initialize basic settings from available API (simplified for bined 0.2.2)
        try {
            viewModeComboBox.setSelectedIndex(codeArea.getViewMode().ordinal());
            codeTypeComboBox.setSelectedIndex(codeArea.getCodeType().ordinal());
            hexCharactersModeComboBox.setSelectedIndex(codeArea.getCodeCharactersCase().ordinal());
            showShadowCursorCheckBox.setSelected(codeArea.isShowMirrorCursor());
            dataSizeTextField.setText(String.valueOf(codeArea.getDataSize()));
            verticalScrollBarVisibilityComboBox.setSelectedIndex(codeArea.getVerticalScrollBarVisibility().ordinal());
            horizontalScrollBarVisibilityComboBox.setSelectedIndex(codeArea.getHorizontalScrollBarVisibility().ordinal());
        } catch (Exception e) {
            // Ignore - some settings may not be available
        }

        // Add caret listener using new API
        codeArea.addCaretMovedListener((CodeAreaCaretPosition caretPosition) -> {
            positionTextField.setText(String.valueOf(caretPosition.getDataPosition()));
            codeOffsetTextField.setText(String.valueOf(caretPosition.getCodeOffset()));
        });

        // Add selection listener
        codeArea.addSelectionChangedListener(() -> {
            SelectionRange selection = codeArea.getSelection();
            if (selection != null) {
                long first = selection.getFirst();
                selectionStartTextField.setText(String.valueOf(first));
                long last = selection.getLast();
                selectionEndTextField.setText(String.valueOf(last));
            } else {
                selectionStartTextField.setText("");
                selectionEndTextField.setText("");
            }
        });

        // Add data changed listener
        codeArea.addDataChangedListener(() -> {
            dataSizeTextField.setText(String.valueOf(codeArea.getDataSize()));
        });

        tabMap.put(modeTab, modePanel);
        tabMap.put(stateTab, statePanel);
        tabMap.put(layoutTab, layoutPanel);
        tabMap.put(decorationTab, decorationPanel);
        tabMap.put(scrollingTab, scrollingPanel);
        tabMap.put(cursorTab, cursorPanel);

        // Create and add Raw tab first (default tab)
        setupRawTab();

        // Create and add Colors tab
        setupColorsTab();

        // Create and add Options tab (after Colors)
        setupOptionsTab();

        // Setup collapsible settings panel
        setupCollapsibleSettings();

        // Hide advanced tabs by default (show only Raw, Options and Colors)
        hideAdvancedTabs();

        activeTab = rawTab;
        rawTab.add(tabMap.get(rawTab), BorderLayout.CENTER);

        // Initialize context menu (if painter is already set)
        initContextMenu();
    }

    // Hide advanced tabs (Mode, State, Layout, Decoration, Scrolling, Cursor)
    private void hideAdvancedTabs() {
        // Remove advanced tabs from tabbedPane (keep Colors and Raw)
        for (int i = tabbedPane.getTabCount() - 1; i >= 0; i--) {
            String title = tabbedPane.getTitleAt(i);
            if (title.equals("Mode") || title.equals("State") || title.equals("Layout") ||
                title.equals("Decoration") || title.equals("Scrolling") || title.equals("Cursor")) {
                tabbedPane.removeTabAt(i);
            }
        }
    }

    // Raw tab setup for bidirectional hex-raw sync
    private void setupRawTab() {
        rawTab = new JPanel(new BorderLayout());

        // Create content panel (following same pattern as other tabs)
        JPanel rawPanel = new JPanel(new BorderLayout());

        // Create raw text area
        rawTextArea = new JTextArea();
        rawTextArea.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        rawTextArea.setLineWrap(true);
        rawTextArea.setWrapStyleWord(false);

        JScrollPane rawScrollPane = new JScrollPane(rawTextArea);
        rawPanel.add(rawScrollPane, BorderLayout.CENTER);

        tabbedPane.addTab("Raw", rawTab);
        tabMap.put(rawTab, rawPanel);

        // Setup bidirectional sync
        setupBidirectionalSync();
    }

    // Bidirectional sync between hex and raw views
    private void setupBidirectionalSync() {
        // Raw to Hex sync
        rawTextArea.getDocument().addDocumentListener(new DocumentListener() {
            @Override
            public void insertUpdate(DocumentEvent e) { syncRawToHex(); }
            @Override
            public void removeUpdate(DocumentEvent e) { syncRawToHex(); }
            @Override
            public void changedUpdate(DocumentEvent e) { syncRawToHex(); }
        });

        // Hex to Raw sync - add listener to codeArea
        codeArea.addDataChangedListener(() -> syncHexToRaw());
    }

    private void syncHexToRaw() {
        if (syncInProgress || rawTextArea == null || codeArea == null || codeArea.getContentData() == null) return;
        syncInProgress = true;
        try {
            long dataSize = codeArea.getDataSize();
            if (dataSize > 0 && dataSize < Integer.MAX_VALUE) {
                byte[] data = new byte[(int) dataSize];
                for (int i = 0; i < dataSize; i++) {
                    data[i] = codeArea.getContentData().getByte(i);
                }
                // Use ISO-8859-1 for lossless byte-to-char mapping
                rawTextArea.setText(new String(data, StandardCharsets.ISO_8859_1));
            } else {
                rawTextArea.setText("");
            }
        } finally {
            syncInProgress = false;
        }
    }

    private void syncRawToHex() {
        if (syncInProgress || rawTextArea == null || codeArea == null || codeArea.getContentData() == null) return;
        syncInProgress = true;
        try {
            String text = rawTextArea.getText();
            // Use ISO-8859-1 for lossless char-to-byte mapping
            byte[] bytes = text.getBytes(StandardCharsets.ISO_8859_1);
            ByteArrayEditableData editableData = (ByteArrayEditableData) codeArea.getContentData();
            editableData.clear();
            if (bytes.length > 0) {
                editableData.insert(0, bytes);
            }
            codeArea.repaint();
            dataSizeTextField.setText(String.valueOf(codeArea.getDataSize()));
        } catch (Exception e) {
            // Ignore sync errors
        } finally {
            syncInProgress = false;
        }
    }

    // Method to sync raw view when message is set externally
    public void updateRawView() {
        syncHexToRaw();
    }

    // Options tab with working settings for bined 0.2.2
    private void setupOptionsTab() {
        optionsTab = new JPanel(new BorderLayout());
        optionsPanel = new JPanel();
        optionsPanel.setLayout(new BoxLayout(optionsPanel, BoxLayout.Y_AXIS));
        optionsPanel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));

        // Font settings panel
        JPanel fontPanel = new JPanel(new GridBagLayout());
        fontPanel.setBorder(BorderFactory.createTitledBorder("Font"));
        fontPanel.setAlignmentX(Component.LEFT_ALIGNMENT);
        GridBagConstraints fgbc = new GridBagConstraints();
        fgbc.insets = new Insets(3, 5, 3, 5);
        fgbc.anchor = GridBagConstraints.WEST;

        // Font family
        String[] fontFamilies = {"Monospaced", "Courier New", "Consolas", "DejaVu Sans Mono", "Liberation Mono"};
        javax.swing.JComboBox<String> fontComboBox = new javax.swing.JComboBox<>(fontFamilies);
        fontComboBox.addActionListener(e -> {
            if (codeArea != null) {
                String fontName = (String) fontComboBox.getSelectedItem();
                Font currentFont = codeArea.getCodeFont();
                int size = currentFont != null ? currentFont.getSize() : 12;
                codeArea.setCodeFont(new Font(fontName, Font.PLAIN, size));
            }
        });
        fgbc.gridx = 0; fgbc.gridy = 0;
        fontPanel.add(new JLabel("Font:"), fgbc);
        fgbc.gridx = 1;
        fontPanel.add(fontComboBox, fgbc);

        // Font size
        Integer[] fontSizes = {10, 11, 12, 13, 14, 16, 18, 20, 24};
        javax.swing.JComboBox<Integer> fontSizeComboBox = new javax.swing.JComboBox<>(fontSizes);
        fontSizeComboBox.setSelectedItem(12);
        fontSizeComboBox.addActionListener(e -> {
            if (codeArea != null) {
                int size = (Integer) fontSizeComboBox.getSelectedItem();
                Font currentFont = codeArea.getCodeFont();
                String fontName = currentFont != null ? currentFont.getFamily() : "Monospaced";
                codeArea.setCodeFont(new Font(fontName, Font.PLAIN, size));
            }
        });
        fgbc.gridx = 0; fgbc.gridy = 1;
        fontPanel.add(new JLabel("Size:"), fgbc);
        fgbc.gridx = 1;
        fontPanel.add(fontSizeComboBox, fgbc);

        // Antialiasing
        String[] antialiasingModes = {"OFF", "AUTO", "DEFAULT", "BASIC", "GASP", "LCD_HRGB", "LCD_HBGR", "LCD_VRGB", "LCD_VBGR"};
        javax.swing.JComboBox<String> antialiasingComboBox = new javax.swing.JComboBox<>(antialiasingModes);
        antialiasingComboBox.setSelectedItem("AUTO");
        antialiasingComboBox.addActionListener(e -> {
            if (codeArea != null) {
                String mode = (String) antialiasingComboBox.getSelectedItem();
                codeArea.setAntialiasingMode(AntialiasingMode.valueOf(mode));
            }
        });
        fgbc.gridx = 0; fgbc.gridy = 2;
        fontPanel.add(new JLabel("Antialiasing:"), fgbc);
        fgbc.gridx = 1;
        fontPanel.add(antialiasingComboBox, fgbc);

        optionsPanel.add(fontPanel);
        optionsPanel.add(Box.createVerticalStrut(10));

        // View settings panel
        JPanel viewPanel = new JPanel(new GridBagLayout());
        viewPanel.setBorder(BorderFactory.createTitledBorder("View"));
        viewPanel.setAlignmentX(Component.LEFT_ALIGNMENT);
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.insets = new Insets(3, 5, 3, 5);
        gbc.anchor = GridBagConstraints.WEST;

        // View Mode
        gbc.gridx = 0; gbc.gridy = 0;
        viewPanel.add(new JLabel("View Mode:"), gbc);
        gbc.gridx = 1;
        viewPanel.add(viewModeComboBox, gbc);

        // Code Type
        gbc.gridx = 0; gbc.gridy = 1;
        viewPanel.add(new JLabel("Code Type:"), gbc);
        gbc.gridx = 1;
        viewPanel.add(codeTypeComboBox, gbc);

        // Hex Characters Case
        gbc.gridx = 0; gbc.gridy = 2;
        viewPanel.add(new JLabel("Hex Case:"), gbc);
        gbc.gridx = 1;
        viewPanel.add(hexCharactersModeComboBox, gbc);

        // Row Wrapping
        String[] wrappingModes = {"No Wrapping", "Wrapping"};
        javax.swing.JComboBox<String> rowWrappingComboBox = new javax.swing.JComboBox<>(wrappingModes);
        rowWrappingComboBox.addActionListener(e -> {
            if (codeArea != null) {
                RowWrappingMode mode = rowWrappingComboBox.getSelectedIndex() == 0 ?
                    RowWrappingMode.NO_WRAPPING : RowWrappingMode.WRAPPING;
                codeArea.setRowWrapping(mode);
            }
        });
        gbc.gridx = 0; gbc.gridy = 3;
        viewPanel.add(new JLabel("Row Wrapping:"), gbc);
        gbc.gridx = 1;
        viewPanel.add(rowWrappingComboBox, gbc);

        // Max Bytes Per Row
        Integer[] bytesPerRowOptions = {8, 16, 24, 32, 48, 64};
        javax.swing.JComboBox<Integer> bytesPerRowComboBox = new javax.swing.JComboBox<>(bytesPerRowOptions);
        bytesPerRowComboBox.setSelectedItem(16);
        bytesPerRowComboBox.addActionListener(e -> {
            if (codeArea != null) {
                codeArea.setMaxBytesPerRow((Integer) bytesPerRowComboBox.getSelectedItem());
            }
        });
        gbc.gridx = 0; gbc.gridy = 4;
        viewPanel.add(new JLabel("Bytes Per Row:"), gbc);
        gbc.gridx = 1;
        viewPanel.add(bytesPerRowComboBox, gbc);

        optionsPanel.add(viewPanel);
        optionsPanel.add(Box.createVerticalStrut(10));

        // Display settings panel
        JPanel displayPanel = new JPanel(new GridBagLayout());
        displayPanel.setBorder(BorderFactory.createTitledBorder("Display"));
        displayPanel.setAlignmentX(Component.LEFT_ALIGNMENT);
        GridBagConstraints dgbc = new GridBagConstraints();
        dgbc.insets = new Insets(3, 5, 3, 5);
        dgbc.anchor = GridBagConstraints.WEST;

        // Show Mirror Cursor
        dgbc.gridx = 0; dgbc.gridy = 0; dgbc.gridwidth = 2;
        displayPanel.add(showShadowCursorCheckBox, dgbc);

        // Scrollbar visibility
        dgbc.gridwidth = 1;
        dgbc.gridx = 0; dgbc.gridy = 1;
        displayPanel.add(new JLabel("Vertical Scrollbar:"), dgbc);
        dgbc.gridx = 1;
        displayPanel.add(verticalScrollBarVisibilityComboBox, dgbc);

        dgbc.gridx = 0; dgbc.gridy = 2;
        displayPanel.add(new JLabel("Horizontal Scrollbar:"), dgbc);
        dgbc.gridx = 1;
        displayPanel.add(horizontalScrollBarVisibilityComboBox, dgbc);

        optionsPanel.add(displayPanel);
        optionsPanel.add(Box.createVerticalStrut(10));

        // Edit settings panel
        JPanel editPanel = new JPanel(new GridBagLayout());
        editPanel.setBorder(BorderFactory.createTitledBorder("Editing"));
        editPanel.setAlignmentX(Component.LEFT_ALIGNMENT);
        GridBagConstraints egbc = new GridBagConstraints();
        egbc.insets = new Insets(3, 5, 3, 5);
        egbc.anchor = GridBagConstraints.WEST;

        // Edit Mode
        String[] editModes = {"Read Only", "Expanding", "Capped", "Inplace"};
        javax.swing.JComboBox<String> editModeComboBox = new javax.swing.JComboBox<>(editModes);
        editModeComboBox.setSelectedIndex(1); // Default to Expanding
        editModeComboBox.addActionListener(e -> {
            if (codeArea != null) {
                EditMode[] modes = EditMode.values();
                codeArea.setEditMode(modes[editModeComboBox.getSelectedIndex()]);
            }
        });
        egbc.gridx = 0; egbc.gridy = 0;
        editPanel.add(new JLabel("Edit Mode:"), egbc);
        egbc.gridx = 1;
        editPanel.add(editModeComboBox, egbc);

        // Edit Operation
        String[] editOps = {"Insert", "Overwrite"};
        javax.swing.JComboBox<String> editOpComboBox = new javax.swing.JComboBox<>(editOps);
        editOpComboBox.addActionListener(e -> {
            if (codeArea != null) {
                EditOperation op = editOpComboBox.getSelectedIndex() == 0 ?
                    EditOperation.INSERT : EditOperation.OVERWRITE;
                codeArea.setEditOperation(op);
            }
        });
        egbc.gridx = 0; egbc.gridy = 1;
        editPanel.add(new JLabel("Edit Operation:"), egbc);
        egbc.gridx = 1;
        editPanel.add(editOpComboBox, egbc);

        // Character Encoding
        String[] charsets = {"UTF-8", "ISO-8859-1", "US-ASCII", "UTF-16", "UTF-16BE", "UTF-16LE"};
        javax.swing.JComboBox<String> charsetComboBox = new javax.swing.JComboBox<>(charsets);
        charsetComboBox.setSelectedItem("UTF-8");
        charsetComboBox.addActionListener(e -> {
            if (codeArea != null) {
                String charsetName = (String) charsetComboBox.getSelectedItem();
                codeArea.setCharset(Charset.forName(charsetName));
            }
        });
        egbc.gridx = 0; egbc.gridy = 2;
        editPanel.add(new JLabel("Encoding:"), egbc);
        egbc.gridx = 1;
        editPanel.add(charsetComboBox, egbc);

        optionsPanel.add(editPanel);
        optionsPanel.add(Box.createVerticalStrut(10));

        // Background settings panel
        JPanel bgPanel = new JPanel(new GridBagLayout());
        bgPanel.setBorder(BorderFactory.createTitledBorder("Background"));
        bgPanel.setAlignmentX(Component.LEFT_ALIGNMENT);
        GridBagConstraints bgbc = new GridBagConstraints();
        bgbc.insets = new Insets(3, 5, 3, 5);
        bgbc.anchor = GridBagConstraints.WEST;

        // Background Paint Mode
        String[] bgModes = {"Transparent", "Plain", "Striped"};
        javax.swing.JComboBox<String> bgModeComboBox = new javax.swing.JComboBox<>(bgModes);
        bgModeComboBox.setSelectedIndex(1); // Default to Plain
        bgModeComboBox.addActionListener(e -> {
            if (codeArea != null) {
                BasicBackgroundPaintMode[] modes = BasicBackgroundPaintMode.values();
                codeArea.setBackgroundPaintMode(modes[bgModeComboBox.getSelectedIndex()]);
            }
        });
        bgbc.gridx = 0; bgbc.gridy = 0;
        bgPanel.add(new JLabel("Paint Mode:"), bgbc);
        bgbc.gridx = 1;
        bgPanel.add(bgModeComboBox, bgbc);

        optionsPanel.add(bgPanel);

        // Add to tabbedPane
        tabbedPane.addTab("Options", optionsTab);
        tabMap.put(optionsTab, optionsPanel);
    }

    // Collapsible settings panel setup
    private void setupCollapsibleSettings() {
        // Create toggle button
        toggleSettingsButton = new JButton("◀");
        toggleSettingsButton.setToolTipText("Collapse settings panel");
        toggleSettingsButton.setMargin(new java.awt.Insets(2, 4, 2, 4));
        toggleSettingsButton.setFocusable(false);
        toggleSettingsButton.addActionListener(e -> toggleSettingsPanel());

        // Create a wrapper panel with button at top
        settingsWrapperPanel = new JPanel(new BorderLayout());
        settingsWrapperPanel.setMinimumSize(new Dimension(MIN_SETTINGS_PANEL_WIDTH_PX, 0));

        // Top bar with toggle button
        JPanel topBar = new JPanel(new BorderLayout());
        topBar.add(toggleSettingsButton, BorderLayout.WEST);
        JLabel settingsLabel = new JLabel(" Settings");
        settingsLabel.setFont(settingsLabel.getFont().deriveFont(Font.BOLD));
        topBar.add(settingsLabel, BorderLayout.CENTER);
        topBar.setBorder(BorderFactory.createEmptyBorder(2, 2, 2, 2));

        settingsWrapperPanel.add(topBar, BorderLayout.NORTH);
        settingsWrapperPanel.add(tabbedPane, BorderLayout.CENTER);

        splitPane.setLeftComponent(settingsWrapperPanel);
        splitPane.setResizeWeight(0.0);

        // Load saved collapsed state
        if (settingsManager != null) {
            settingsCollapsed = settingsManager.loadBoolean(SettingsManager.KEY_SETTINGS_COLLAPSED, false);
            lastDividerLocation = settingsManager.loadInt(SettingsManager.KEY_SETTINGS_DIVIDER_LOCATION, 200);
            if (settingsCollapsed) {
                // Apply collapsed state after a short delay to allow UI to initialize
                javax.swing.SwingUtilities.invokeLater(() -> {
                    splitPane.setDividerLocation(0);
                    toggleSettingsButton.setText("▶");
                    toggleSettingsButton.setToolTipText("Expand settings panel");
                    if (expandSettingsLink != null) {
                        expandSettingsLink.setVisible(true);
                    }
                });
            } else {
                // Apply after layout to avoid first-paint sizing races.
                scheduleDividerLocationApply(getDesiredSettingsPanelWidthPx(), 3);
            }
        }
    }

    private int getDesiredSettingsPanelWidthPx() {
        int desired = lastDividerLocation > 50 ? lastDividerLocation : DEFAULT_SETTINGS_PANEL_WIDTH_PX;
        desired = Math.max(desired, MIN_SETTINGS_PANEL_WIDTH_PX);
        if (settingsWrapperPanel != null) {
            desired = Math.max(desired, settingsWrapperPanel.getPreferredSize().width);
        }
        return desired;
    }

    private void scheduleDividerLocationApply(int desiredPx, int attempts) {
        if (attempts <= 0) return;
        javax.swing.SwingUtilities.invokeLater(() -> {
            // If the split pane hasn't been laid out yet, retry on the next EDT turn.
            if (splitPane.getWidth() <= 0) {
                scheduleDividerLocationApply(desiredPx, attempts - 1);
                return;
            }

            // Keep enough room for the right (hex) side so the editor doesn't get crushed.
            int max = Math.max(MIN_SETTINGS_PANEL_WIDTH_PX, splitPane.getWidth() - 150);
            int clamped = Math.max(MIN_SETTINGS_PANEL_WIDTH_PX, Math.min(desiredPx, max));
            splitPane.setDividerLocation(clamped);
            splitPane.revalidate();
        });
    }

    private void toggleSettingsPanel() {
        if (settingsCollapsed) {
            // Expand
            // Uncollapse immediately, then apply the desired divider location after layout.
            splitPane.setDividerLocation(1);
            toggleSettingsButton.setText("◀");
            toggleSettingsButton.setToolTipText("Collapse settings panel");
            settingsCollapsed = false;
            if (expandSettingsLink != null) {
                expandSettingsLink.setVisible(false);
            }
            scheduleDividerLocationApply(getDesiredSettingsPanelWidthPx(), 3);
        } else {
            // Collapse - store current location first
            lastDividerLocation = splitPane.getDividerLocation();
            splitPane.setDividerLocation(0);
            toggleSettingsButton.setText("▶");
            toggleSettingsButton.setToolTipText("Expand settings panel");
            settingsCollapsed = true;
            if (expandSettingsLink != null) {
                expandSettingsLink.setVisible(true);
            }
        }

        // Persist state
        if (settingsManager != null) {
            settingsManager.saveBoolean(SettingsManager.KEY_SETTINGS_COLLAPSED, settingsCollapsed);
            settingsManager.saveInt(SettingsManager.KEY_SETTINGS_DIVIDER_LOCATION, lastDividerLocation);
        }
    }

    // Colors tab setup
    private void setupColorsTab() {
        colorsTab = new JPanel(new BorderLayout());
        colorsPanel = new JPanel();
        colorsPanel.setLayout(new BoxLayout(colorsPanel, BoxLayout.Y_AXIS));
        colorsPanel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));

        // Theme selector panel
        JPanel themePanel = new JPanel(new GridBagLayout());
        themePanel.setBorder(BorderFactory.createTitledBorder("Theme"));
        themePanel.setAlignmentX(Component.LEFT_ALIGNMENT);
        GridBagConstraints tgbc = new GridBagConstraints();
        tgbc.insets = new Insets(3, 5, 3, 5);
        tgbc.anchor = GridBagConstraints.WEST;

        tgbc.gridx = 0; tgbc.gridy = 0;
        themePanel.add(new JLabel("Select Theme:"), tgbc);

        tgbc.gridx = 1;
        themeComboBox = new javax.swing.JComboBox<>(new String[]{
            "Light", "Dark", "High Contrast", "Monokai", "Solarized Dark",
            "Solarized Light", "Matrix", "Dracula", "Ocean", "Retro", "Custom"
        });
        themeComboBox.addActionListener(e -> {
            if (!suppressThemeComboEvents) {
                applySelectedTheme();
            }
        });
        themePanel.add(themeComboBox, tgbc);

        colorsPanel.add(themePanel);
        colorsPanel.add(Box.createVerticalStrut(10));

        // Character Colors Section - using GridBagLayout for proper alignment
        JPanel charColorsPanel = new JPanel(new GridBagLayout());
        charColorsPanel.setBorder(BorderFactory.createTitledBorder("Character Colors (Text + Background)"));
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.insets = new Insets(3, 5, 3, 5);
        gbc.anchor = GridBagConstraints.WEST;

        // Header row
        gbc.gridy = 0;
        gbc.gridx = 0; charColorsPanel.add(new JLabel("Type"), gbc);
        gbc.gridx = 1; charColorsPanel.add(new JLabel("Text"), gbc);
        gbc.gridx = 2; charColorsPanel.add(new JLabel(""), gbc); // Spacer
        gbc.gridx = 3; charColorsPanel.add(new JLabel("Background"), gbc);

        // Printable characters
        printableColorButton = createColorButton("Printable", Color.BLACK);
        printableBgButton = createColorButton("Bg", Color.WHITE);
        printableBgCheckBox = new javax.swing.JCheckBox("Custom");
        printableBgButton.setEnabled(false);
        gbc.gridy = 1;
        gbc.gridx = 0; charColorsPanel.add(new JLabel("Printable:"), gbc);
        gbc.gridx = 1; charColorsPanel.add(printableColorButton, gbc);
        gbc.gridx = 2; charColorsPanel.add(printableBgCheckBox, gbc);
        gbc.gridx = 3; charColorsPanel.add(printableBgButton, gbc);

        // Null byte characters
        nullByteColorButton = createColorButton("Null Byte", Color.RED);
        nullByteBgButton = createColorButton("Bg", Color.WHITE);
        nullByteBgCheckBox = new javax.swing.JCheckBox("Custom");
        nullByteBgButton.setEnabled(false);
        gbc.gridy = 2;
        gbc.gridx = 0; charColorsPanel.add(new JLabel("Null Byte:"), gbc);
        gbc.gridx = 1; charColorsPanel.add(nullByteColorButton, gbc);
        gbc.gridx = 2; charColorsPanel.add(nullByteBgCheckBox, gbc);
        gbc.gridx = 3; charColorsPanel.add(nullByteBgButton, gbc);

        // Unprintable characters
        unprintableColorButton = createColorButton("Unprintable", Color.BLUE);
        unprintableBgButton = createColorButton("Bg", Color.WHITE);
        unprintableBgCheckBox = new javax.swing.JCheckBox("Custom");
        unprintableBgButton.setEnabled(false);
        gbc.gridy = 3;
        gbc.gridx = 0; charColorsPanel.add(new JLabel("Unprintable:"), gbc);
        gbc.gridx = 1; charColorsPanel.add(unprintableColorButton, gbc);
        gbc.gridx = 2; charColorsPanel.add(unprintableBgCheckBox, gbc);
        gbc.gridx = 3; charColorsPanel.add(unprintableBgButton, gbc);

        // Space characters
        spaceColorButton = createColorButton("Space", Color.BLACK);
        spaceBgButton = createColorButton("Bg", Color.WHITE);
        spaceBgCheckBox = new javax.swing.JCheckBox("Custom");
        spaceBgButton.setEnabled(false);
        gbc.gridy = 4;
        gbc.gridx = 0; charColorsPanel.add(new JLabel("Space:"), gbc);
        gbc.gridx = 1; charColorsPanel.add(spaceColorButton, gbc);
        gbc.gridx = 2; charColorsPanel.add(spaceBgCheckBox, gbc);
        gbc.gridx = 3; charColorsPanel.add(spaceBgButton, gbc);

        // Region Colors Section — context-aware (HTTP vs WebSocket)
        JPanel regionColorsPanel = new JPanel(new GridBagLayout());
        GridBagConstraints rgbc = new GridBagConstraints();
        rgbc.insets = new Insets(3, 5, 3, 5);
        rgbc.anchor = GridBagConstraints.WEST;

        if (webSocketMode) {
            regionColorsPanel.setBorder(BorderFactory.createTitledBorder("WebSocket Syntax Colors"));

            regionColoringCheckBox = new javax.swing.JCheckBox("Enable syntax coloring");
            regionColoringCheckBox.setSelected(true);
            rgbc.gridy = 0; rgbc.gridx = 0; rgbc.gridwidth = 2;
            regionColorsPanel.add(regionColoringCheckBox, rgbc);
            rgbc.gridwidth = 1;

            wsKeyBgButton = createColorButton("Key", new Color(255, 243, 179));
            wsStringBgButton = createColorButton("String", new Color(200, 245, 200));
            wsNumberBgButton = createColorButton("Number", new Color(194, 229, 255));
            wsStructureBgButton = createColorButton("Structure", new Color(224, 224, 224));
            wsLiteralBgButton = createColorButton("Literal", new Color(229, 204, 255));
            wsBinaryBgButton = createColorButton("Binary", new Color(255, 204, 204));
            wsDefaultBgButton = createColorButton("Default", new Color(255, 255, 255));

            rgbc.gridy = 1; rgbc.gridx = 0; regionColorsPanel.add(new JLabel("Key:"), rgbc);
            rgbc.gridx = 1; regionColorsPanel.add(wsKeyBgButton, rgbc);

            rgbc.gridy = 2; rgbc.gridx = 0; regionColorsPanel.add(new JLabel("String:"), rgbc);
            rgbc.gridx = 1; regionColorsPanel.add(wsStringBgButton, rgbc);

            rgbc.gridy = 3; rgbc.gridx = 0; regionColorsPanel.add(new JLabel("Number:"), rgbc);
            rgbc.gridx = 1; regionColorsPanel.add(wsNumberBgButton, rgbc);

            rgbc.gridy = 4; rgbc.gridx = 0; regionColorsPanel.add(new JLabel("Structure:"), rgbc);
            rgbc.gridx = 1; regionColorsPanel.add(wsStructureBgButton, rgbc);

            rgbc.gridy = 5; rgbc.gridx = 0; regionColorsPanel.add(new JLabel("Literal:"), rgbc);
            rgbc.gridx = 1; regionColorsPanel.add(wsLiteralBgButton, rgbc);

            rgbc.gridy = 6; rgbc.gridx = 0; regionColorsPanel.add(new JLabel("Binary:"), rgbc);
            rgbc.gridx = 1; regionColorsPanel.add(wsBinaryBgButton, rgbc);

            rgbc.gridy = 7; rgbc.gridx = 0; regionColorsPanel.add(new JLabel("Default:"), rgbc);
            rgbc.gridx = 1; regionColorsPanel.add(wsDefaultBgButton, rgbc);

            regionColoringCheckBox.addActionListener(e -> {
                boolean enabled = regionColoringCheckBox.isSelected();
                wsKeyBgButton.setEnabled(enabled);
                wsStringBgButton.setEnabled(enabled);
                wsNumberBgButton.setEnabled(enabled);
                wsStructureBgButton.setEnabled(enabled);
                wsLiteralBgButton.setEnabled(enabled);
                wsBinaryBgButton.setEnabled(enabled);
                wsDefaultBgButton.setEnabled(enabled);
                if (hextraPainter != null) {
                    hextraPainter.setRegionColoringEnabled(enabled);
                    codeArea.repaint();
                }
                if (settingsManager != null) {
                    settingsManager.saveSetting(SettingsManager.KEY_WS_COLORING_ENABLED, String.valueOf(enabled));
                }
            });
        } else {
            regionColorsPanel.setBorder(BorderFactory.createTitledBorder("HTTP Region Background Colors"));

            regionColoringCheckBox = new javax.swing.JCheckBox("Enable HTTP region coloring");
            regionColoringCheckBox.setSelected(true);
            rgbc.gridy = 0; rgbc.gridx = 0; rgbc.gridwidth = 2;
            regionColorsPanel.add(regionColoringCheckBox, rgbc);
            rgbc.gridwidth = 1;

            requestLineBgButton = createColorButton("Request Line", new Color(255, 245, 238));
            headersBgButton = createColorButton("Headers", new Color(240, 255, 240));
            bodyBgButton = createColorButton("Body", new Color(240, 248, 255));
            defaultBgButton = createColorButton("Default", new Color(255, 255, 255));

            rgbc.gridy = 1; rgbc.gridx = 0; regionColorsPanel.add(new JLabel("Request Line:"), rgbc);
            rgbc.gridx = 1; regionColorsPanel.add(requestLineBgButton, rgbc);

            rgbc.gridy = 2; rgbc.gridx = 0; regionColorsPanel.add(new JLabel("Headers:"), rgbc);
            rgbc.gridx = 1; regionColorsPanel.add(headersBgButton, rgbc);

            rgbc.gridy = 3; rgbc.gridx = 0; regionColorsPanel.add(new JLabel("Body:"), rgbc);
            rgbc.gridx = 1; regionColorsPanel.add(bodyBgButton, rgbc);

            rgbc.gridy = 4; rgbc.gridx = 0; regionColorsPanel.add(new JLabel("Default:"), rgbc);
            rgbc.gridx = 1; regionColorsPanel.add(defaultBgButton, rgbc);

            regionColoringCheckBox.addActionListener(e -> {
                boolean enabled = regionColoringCheckBox.isSelected();
                requestLineBgButton.setEnabled(enabled);
                headersBgButton.setEnabled(enabled);
                bodyBgButton.setEnabled(enabled);
                defaultBgButton.setEnabled(enabled);
                if (hextraPainter != null) {
                    hextraPainter.setRegionColoringEnabled(enabled);
                    codeArea.repaint();
                }
                if (settingsManager != null) {
                    settingsManager.saveSetting(SettingsManager.KEY_REGION_COLORING_ENABLED, String.valueOf(enabled));
                }
            });
        }

        // Reset to Defaults button
        JPanel resetPanel = new JPanel();
        resetPanel.setLayout(new BoxLayout(resetPanel, BoxLayout.X_AXIS));
        resetPanel.setBorder(BorderFactory.createEmptyBorder(10, 0, 0, 0));
        JButton resetButton = new JButton("Reset to Defaults");
        resetButton.addActionListener(e -> resetAllSettings());
        resetPanel.add(resetButton);
        resetPanel.add(Box.createHorizontalGlue());

        colorsPanel.add(charColorsPanel);
        colorsPanel.add(Box.createVerticalStrut(10));
        colorsPanel.add(regionColorsPanel);
        colorsPanel.add(Box.createVerticalStrut(10));
        colorsPanel.add(resetPanel);

        // Follow the same pattern as other tabs - don't add content directly
        // The tabbedPaneStateChanged handler will manage adding/removing content
        tabbedPane.addTab("Colors", colorsTab);
        tabMap.put(colorsTab, colorsPanel);

        // Now that buttons exist, set up listeners and load colors
        setupColorButtonListeners();
        loadColorSettings();
    }

    private JButton createColorButton(String name, Color defaultColor) {
        JButton button = new JButton();
        button.setBackground(defaultColor);
        button.setOpaque(true);
        button.setPreferredSize(new Dimension(60, 25));
        button.setMaximumSize(new Dimension(60, 25));
        return button;
    }


    // Settings manager
    public void setSettingsManager(SettingsManager manager) {
        this.settingsManager = manager;
        loadSettings();
        // Load color settings if painter is already set
        if (hextraPainter != null) {
            loadColorSettings();
        }
        setupColorButtonListeners();
    }

    public void setPainter(HextraCodeAreaPainter painter) {
        this.hextraPainter = painter;
        // Load color settings if settingsManager is already set
        if (settingsManager != null) {
            loadColorSettings();
        }
        // Initialize search panel now that we have the painter
        initSearchPanel();
        // Initialize context menu
        initContextMenu();
    }

    private void initSearchPanel() {
        if (codeArea == null || hextraPainter == null) return;
        if (searchPanel != null) return; // Already initialized

        searchPanel = new SearchPanel(codeArea, hextraPainter);
        searchPanel.setVisible(false);

        // Add search panel to the top of hex area wrapper
        Component topComponent = hexAreaWrapper.getComponent(0);
        if (topComponent instanceof JPanel) {
            JPanel topPanel = (JPanel) topComponent;
            topPanel.add(searchPanel, BorderLayout.CENTER);
        }
    }

    private void initContextMenu() {
        if (codeArea == null || hextraPainter == null) return;
        if (contextMenu != null) return; // Already initialized

        // Create context menu with region parser from painter
        contextMenu = new HexContextMenu(codeArea, hextraPainter.getRegionParser());

        // Try Swing's built-in popup menu mechanism
        codeArea.setComponentPopupMenu(contextMenu);
        codeArea.setInheritsPopupMenu(true);

        // Also add manual mouse listener as fallback (some components need this)
        java.awt.event.MouseAdapter popupListener = new java.awt.event.MouseAdapter() {
            @Override
            public void mousePressed(java.awt.event.MouseEvent e) {
                maybeShowPopup(e);
            }

            @Override
            public void mouseReleased(java.awt.event.MouseEvent e) {
                maybeShowPopup(e);
            }

            private void maybeShowPopup(java.awt.event.MouseEvent e) {
                if (e.isPopupTrigger()) {
                    contextMenu.updateMenuState();
                    contextMenu.show(e.getComponent(), e.getX(), e.getY());
                }
            }
        };
        codeArea.addMouseListener(popupListener);

        // Add listener to update menu state before showing (for setComponentPopupMenu)
        contextMenu.addPopupMenuListener(new javax.swing.event.PopupMenuListener() {
            @Override
            public void popupMenuWillBecomeVisible(javax.swing.event.PopupMenuEvent e) {
                contextMenu.updateMenuState();
            }

            @Override
            public void popupMenuWillBecomeInvisible(javax.swing.event.PopupMenuEvent e) {}

            @Override
            public void popupMenuCanceled(javax.swing.event.PopupMenuEvent e) {}
        });
    }

    private void showSearchPanel() {
        // Initialize search panel if not done yet
        if (searchPanel == null) {
            initSearchPanel();
        }
        if (searchPanel != null) {
            searchPanel.showPanel();
        }
    }

    // Alias for setPainter - HextraCodeAreaPainter is now a ColorAssessor
    public void setColorAssessor(HextraCodeAreaPainter colorAssessor) {
        setPainter(colorAssessor);
    }

    /**
     * Set WebSocket mode — changes the Colors tab to show WS-relevant
     * region colors instead of HTTP region colors.
     * Must be called before {@link #setCodeArea} which builds the UI.
     */
    public void setWebSocketMode(boolean wsMode) {
        this.webSocketMode = wsMode;
    }

    /**
     * Get the parent frame for dialogs (required by BApp Store criteria)
     */
    private Frame getParentFrame() {
        Window window = SwingUtilities.getWindowAncestor(this);
        if (window instanceof Frame) {
            return (Frame) window;
        }
        return null;
    }

    private void setupColorButtonListeners() {
        if (hextraPainter == null) return;
        // Color buttons may not exist if Colors tab wasn't set up
        if (printableColorButton == null) return;

        printableColorButton.addActionListener(e -> {
            Color newColor = JColorChooser.showDialog(getParentFrame(), "Printable Character Color", hextraPainter.getPrintableColor());
            if (newColor != null) {
                hextraPainter.setPrintableColor(newColor);
                printableColorButton.setBackground(newColor);
                codeArea.resetPainter();
                codeArea.repaint();
                if (settingsManager != null) {
                    settingsManager.saveColor(SettingsManager.KEY_PRINTABLE_COLOR, newColor);
                }
            }
        });

        nullByteColorButton.addActionListener(e -> {
            Color newColor = JColorChooser.showDialog(getParentFrame(), "Null Byte Color", hextraPainter.getNullByteColor());
            if (newColor != null) {
                hextraPainter.setNullByteColor(newColor);
                nullByteColorButton.setBackground(newColor);
                codeArea.resetPainter();
                codeArea.repaint();
                if (settingsManager != null) {
                    settingsManager.saveColor(SettingsManager.KEY_NULL_BYTE_COLOR, newColor);
                }
            }
        });

        unprintableColorButton.addActionListener(e -> {
            Color newColor = JColorChooser.showDialog(getParentFrame(), "Unprintable Character Color", hextraPainter.getUnprintableColor());
            if (newColor != null) {
                hextraPainter.setUnprintableColor(newColor);
                unprintableColorButton.setBackground(newColor);
                codeArea.resetPainter();
                codeArea.repaint();
                if (settingsManager != null) {
                    settingsManager.saveColor(SettingsManager.KEY_UNPRINTABLE_COLOR, newColor);
                }
            }
        });

        spaceColorButton.addActionListener(e -> {
            Color newColor = JColorChooser.showDialog(getParentFrame(), "Space Character Color", hextraPainter.getSpaceColor());
            if (newColor != null) {
                hextraPainter.setSpaceColor(newColor);
                spaceColorButton.setBackground(newColor);
                codeArea.resetPainter();
                codeArea.repaint();
                if (settingsManager != null) {
                    settingsManager.saveColor(SettingsManager.KEY_SPACE_COLOR, newColor);
                }
            }
        });

        if (webSocketMode) {
            // WS region color button listeners
            setupWsColorButton(wsKeyBgButton, "Key Background",
                () -> hextraPainter.getWsKeyBg(), c -> hextraPainter.setWsKeyBg(c), SettingsManager.KEY_WS_KEY_BG);
            setupWsColorButton(wsStringBgButton, "String Background",
                () -> hextraPainter.getWsStringBg(), c -> hextraPainter.setWsStringBg(c), SettingsManager.KEY_WS_STRING_BG);
            setupWsColorButton(wsNumberBgButton, "Number Background",
                () -> hextraPainter.getWsNumberBg(), c -> hextraPainter.setWsNumberBg(c), SettingsManager.KEY_WS_NUMBER_BG);
            setupWsColorButton(wsStructureBgButton, "Structure Background",
                () -> hextraPainter.getWsStructureBg(), c -> hextraPainter.setWsStructureBg(c), SettingsManager.KEY_WS_STRUCTURE_BG);
            setupWsColorButton(wsLiteralBgButton, "Literal Background",
                () -> hextraPainter.getWsLiteralBg(), c -> hextraPainter.setWsLiteralBg(c), SettingsManager.KEY_WS_LITERAL_BG);
            setupWsColorButton(wsBinaryBgButton, "Binary Background",
                () -> hextraPainter.getWsBinaryBg(), c -> hextraPainter.setWsBinaryBg(c), SettingsManager.KEY_WS_BINARY_BG);
            setupWsColorButton(wsDefaultBgButton, "Default Background",
                () -> hextraPainter.getWsDefaultBg(), c -> hextraPainter.setWsDefaultBg(c), SettingsManager.KEY_WS_DEFAULT_BG);
        } else {
            requestLineBgButton.addActionListener(e -> {
                Color newColor = JColorChooser.showDialog(getParentFrame(), "Request Line Background", hextraPainter.getRequestLineBgColor());
                if (newColor != null) {
                    hextraPainter.setRequestLineBgColor(newColor);
                    requestLineBgButton.setBackground(newColor);
                    codeArea.repaint();
                    if (settingsManager != null) {
                        settingsManager.saveColor(SettingsManager.KEY_REQUEST_LINE_BG, newColor);
                    }
                }
            });

            headersBgButton.addActionListener(e -> {
                Color newColor = JColorChooser.showDialog(getParentFrame(), "Headers Background", hextraPainter.getHeadersBgColor());
                if (newColor != null) {
                    hextraPainter.setHeadersBgColor(newColor);
                    headersBgButton.setBackground(newColor);
                    codeArea.repaint();
                    if (settingsManager != null) {
                        settingsManager.saveColor(SettingsManager.KEY_HEADERS_BG, newColor);
                    }
                }
            });

            bodyBgButton.addActionListener(e -> {
                Color newColor = JColorChooser.showDialog(getParentFrame(), "Body Background", hextraPainter.getBodyBgColor());
                if (newColor != null) {
                    hextraPainter.setBodyBgColor(newColor);
                    bodyBgButton.setBackground(newColor);
                    codeArea.repaint();
                    if (settingsManager != null) {
                        settingsManager.saveColor(SettingsManager.KEY_BODY_BG, newColor);
                    }
                }
            });

            defaultBgButton.addActionListener(e -> {
                Color newColor = JColorChooser.showDialog(getParentFrame(), "Default Background", hextraPainter.getDefaultBgColor());
                if (newColor != null) {
                    hextraPainter.setDefaultBgColor(newColor);
                    defaultBgButton.setBackground(newColor);
                    codeArea.repaint();
                    if (settingsManager != null) {
                        settingsManager.saveColor(SettingsManager.KEY_DEFAULT_BG, newColor);
                    }
                }
            });
        }

        // Character background checkboxes and buttons
        setupCharBgListeners(printableBgCheckBox, printableBgButton,
            () -> hextraPainter.getPrintableBgColor(),
            c -> hextraPainter.setPrintableBgColor(c),
            SettingsManager.KEY_PRINTABLE_BG, "Printable Background");

        setupCharBgListeners(nullByteBgCheckBox, nullByteBgButton,
            () -> hextraPainter.getNullByteBgColor(),
            c -> hextraPainter.setNullByteBgColor(c),
            SettingsManager.KEY_NULL_BYTE_BG, "Null Byte Background");

        setupCharBgListeners(unprintableBgCheckBox, unprintableBgButton,
            () -> hextraPainter.getUnprintableBgColor(),
            c -> hextraPainter.setUnprintableBgColor(c),
            SettingsManager.KEY_UNPRINTABLE_BG, "Unprintable Background");

        setupCharBgListeners(spaceBgCheckBox, spaceBgButton,
            () -> hextraPainter.getSpaceBgColor(),
            c -> hextraPainter.setSpaceBgColor(c),
            SettingsManager.KEY_SPACE_BG, "Space Background");
    }

    private void setupCharBgListeners(javax.swing.JCheckBox checkBox, JButton button,
                                       java.util.function.Supplier<Color> getter,
                                       java.util.function.Consumer<Color> setter,
                                       String settingsKey, String dialogTitle) {
        // Checkbox enables/disables custom background
        checkBox.addActionListener(e -> {
            boolean useCustom = checkBox.isSelected();
            button.setEnabled(useCustom);
            if (!useCustom) {
                // Reset to region background (null)
                setter.accept(null);
                button.setBackground(Color.WHITE);
                codeArea.repaint();
                if (settingsManager != null) {
                    settingsManager.saveSetting(settingsKey, "");
                }
            }
        });

        // Button opens color picker
        button.addActionListener(e -> {
            Color currentColor = getter.get();
            if (currentColor == null) currentColor = Color.WHITE;
            Color newColor = JColorChooser.showDialog(getParentFrame(), dialogTitle, currentColor);
            if (newColor != null) {
                setter.accept(newColor);
                button.setBackground(newColor);
                codeArea.repaint();
                if (settingsManager != null) {
                    settingsManager.saveColor(settingsKey, newColor);
                }
            }
        });
    }

    private void setupWsColorButton(JButton button, String dialogTitle,
                                      java.util.function.Supplier<Color> getter,
                                      java.util.function.Consumer<Color> setter,
                                      String settingsKey) {
        if (button == null) return;
        button.addActionListener(e -> {
            Color currentColor = getter.get();
            if (currentColor == null) currentColor = Color.WHITE;
            Color newColor = JColorChooser.showDialog(getParentFrame(), dialogTitle, currentColor);
            if (newColor != null) {
                setter.accept(newColor);
                button.setBackground(newColor);
                codeArea.repaint();
                if (settingsManager != null) {
                    settingsManager.saveColor(settingsKey, newColor);
                }
            }
        });
    }

    private void loadSettings() {
        if (settingsManager == null) return;

        // Load settings if codeArea is available
        if (codeArea != null) {
            int viewMode = settingsManager.loadInt(SettingsManager.KEY_VIEW_MODE, codeArea.getViewMode().ordinal());
            if (viewMode >= 0 && viewMode < CodeAreaViewMode.values().length) {
                codeArea.setViewMode(CodeAreaViewMode.values()[viewMode]);
                viewModeComboBox.setSelectedIndex(viewMode);
            }

            int codeType = settingsManager.loadInt(SettingsManager.KEY_CODE_TYPE, codeArea.getCodeType().ordinal());
            if (codeType >= 0 && codeType < CodeType.values().length) {
                codeArea.setCodeType(CodeType.values()[codeType]);
                codeTypeComboBox.setSelectedIndex(codeType);
            }

            // Note: showLineNumbers, showHeader, showUnprintableCharacters not available in bined 0.2.2
            // These settings are no longer supported by the new library
        }
    }

    private void loadColorSettings() {
        if (settingsManager == null || hextraPainter == null) return;

        // Load character colors
        Color printableColor = settingsManager.loadColor(SettingsManager.KEY_PRINTABLE_COLOR, Color.BLACK);
        hextraPainter.setPrintableColor(printableColor);
        if (printableColorButton != null) printableColorButton.setBackground(printableColor);

        Color nullByteColor = settingsManager.loadColor(SettingsManager.KEY_NULL_BYTE_COLOR, Color.RED);
        hextraPainter.setNullByteColor(nullByteColor);
        if (nullByteColorButton != null) nullByteColorButton.setBackground(nullByteColor);

        Color unprintableColor = settingsManager.loadColor(SettingsManager.KEY_UNPRINTABLE_COLOR, Color.BLUE);
        hextraPainter.setUnprintableColor(unprintableColor);
        if (unprintableColorButton != null) unprintableColorButton.setBackground(unprintableColor);

        Color spaceColor = settingsManager.loadColor(SettingsManager.KEY_SPACE_COLOR, Color.BLACK);
        hextraPainter.setSpaceColor(spaceColor);
        if (spaceColorButton != null) spaceColorButton.setBackground(spaceColor);

        // Load region coloring enabled setting (separate keys for HTTP and WS)
        String enabledKey = webSocketMode ? SettingsManager.KEY_WS_COLORING_ENABLED : SettingsManager.KEY_REGION_COLORING_ENABLED;
        String regionColoringStr = settingsManager.loadSetting(enabledKey, "true");
        boolean regionColoringEnabled = Boolean.parseBoolean(regionColoringStr);
        hextraPainter.setRegionColoringEnabled(regionColoringEnabled);
        if (regionColoringCheckBox != null) {
            regionColoringCheckBox.setSelected(regionColoringEnabled);
        }

        if (webSocketMode) {
            // Load WebSocket region colors
            Color wsKeyBg = settingsManager.loadColor(SettingsManager.KEY_WS_KEY_BG, new Color(255, 243, 179));
            hextraPainter.setWsKeyBg(wsKeyBg);
            if (wsKeyBgButton != null) { wsKeyBgButton.setBackground(wsKeyBg); wsKeyBgButton.setEnabled(regionColoringEnabled); }

            Color wsStringBg = settingsManager.loadColor(SettingsManager.KEY_WS_STRING_BG, new Color(200, 245, 200));
            hextraPainter.setWsStringBg(wsStringBg);
            if (wsStringBgButton != null) { wsStringBgButton.setBackground(wsStringBg); wsStringBgButton.setEnabled(regionColoringEnabled); }

            Color wsNumberBg = settingsManager.loadColor(SettingsManager.KEY_WS_NUMBER_BG, new Color(194, 229, 255));
            hextraPainter.setWsNumberBg(wsNumberBg);
            if (wsNumberBgButton != null) { wsNumberBgButton.setBackground(wsNumberBg); wsNumberBgButton.setEnabled(regionColoringEnabled); }

            Color wsStructureBg = settingsManager.loadColor(SettingsManager.KEY_WS_STRUCTURE_BG, new Color(224, 224, 224));
            hextraPainter.setWsStructureBg(wsStructureBg);
            if (wsStructureBgButton != null) { wsStructureBgButton.setBackground(wsStructureBg); wsStructureBgButton.setEnabled(regionColoringEnabled); }

            Color wsLiteralBg = settingsManager.loadColor(SettingsManager.KEY_WS_LITERAL_BG, new Color(229, 204, 255));
            hextraPainter.setWsLiteralBg(wsLiteralBg);
            if (wsLiteralBgButton != null) { wsLiteralBgButton.setBackground(wsLiteralBg); wsLiteralBgButton.setEnabled(regionColoringEnabled); }

            Color wsBinaryBg = settingsManager.loadColor(SettingsManager.KEY_WS_BINARY_BG, new Color(255, 204, 204));
            hextraPainter.setWsBinaryBg(wsBinaryBg);
            if (wsBinaryBgButton != null) { wsBinaryBgButton.setBackground(wsBinaryBg); wsBinaryBgButton.setEnabled(regionColoringEnabled); }

            Color wsDefaultBg = settingsManager.loadColor(SettingsManager.KEY_WS_DEFAULT_BG, new Color(255, 255, 255));
            hextraPainter.setWsDefaultBg(wsDefaultBg);
            if (wsDefaultBgButton != null) { wsDefaultBgButton.setBackground(wsDefaultBg); wsDefaultBgButton.setEnabled(regionColoringEnabled); }
        } else {
            // Load HTTP region colors
            if (requestLineBgButton != null) requestLineBgButton.setEnabled(regionColoringEnabled);
            if (headersBgButton != null) headersBgButton.setEnabled(regionColoringEnabled);
            if (bodyBgButton != null) bodyBgButton.setEnabled(regionColoringEnabled);
            if (defaultBgButton != null) defaultBgButton.setEnabled(regionColoringEnabled);

            Color requestLineBg = settingsManager.loadColor(SettingsManager.KEY_REQUEST_LINE_BG, new Color(255, 245, 238));
            hextraPainter.setRequestLineBgColor(requestLineBg);
            if (requestLineBgButton != null) requestLineBgButton.setBackground(requestLineBg);

            Color headersBg = settingsManager.loadColor(SettingsManager.KEY_HEADERS_BG, new Color(240, 255, 240));
            hextraPainter.setHeadersBgColor(headersBg);
            if (headersBgButton != null) headersBgButton.setBackground(headersBg);

            Color bodyBg = settingsManager.loadColor(SettingsManager.KEY_BODY_BG, new Color(240, 248, 255));
            hextraPainter.setBodyBgColor(bodyBg);
            if (bodyBgButton != null) bodyBgButton.setBackground(bodyBg);

            Color defaultBg = settingsManager.loadColor(SettingsManager.KEY_DEFAULT_BG, new Color(255, 255, 255));
            hextraPainter.setDefaultBgColor(defaultBg);
            if (defaultBgButton != null) defaultBgButton.setBackground(defaultBg);
        }

        // Load character background colors (null means use region background)
        loadCharBgSetting(SettingsManager.KEY_PRINTABLE_BG, printableBgCheckBox, printableBgButton,
            c -> hextraPainter.setPrintableBgColor(c));
        loadCharBgSetting(SettingsManager.KEY_NULL_BYTE_BG, nullByteBgCheckBox, nullByteBgButton,
            c -> hextraPainter.setNullByteBgColor(c));
        loadCharBgSetting(SettingsManager.KEY_UNPRINTABLE_BG, unprintableBgCheckBox, unprintableBgButton,
            c -> hextraPainter.setUnprintableBgColor(c));
        loadCharBgSetting(SettingsManager.KEY_SPACE_BG, spaceBgCheckBox, spaceBgButton,
            c -> hextraPainter.setSpaceBgColor(c));

        // Load saved theme name and set combo box selection.
        // null means no theme was ever saved: apply the default theme and persist it.
        String savedTheme = settingsManager.loadSetting(SettingsManager.KEY_CURRENT_THEME, null);
        if (savedTheme == null) {
            savedTheme = "High Contrast";
            applyThemeByName(savedTheme, true);
        }

        // Only restore combo box selection (do not apply theme for returning users, since colors are persisted).
        if (themeComboBox != null) {
            suppressThemeComboEvents = true;
            try {
                themeComboBox.setSelectedItem(savedTheme);
            } finally {
                suppressThemeComboEvents = false;
            }
        }
    }

    private void loadCharBgSetting(String key, javax.swing.JCheckBox checkBox, JButton button,
                                    java.util.function.Consumer<Color> setter) {
        String value = settingsManager.loadSetting(key, "");
        if (value != null && !value.isEmpty()) {
            try {
                Color color = new Color(Integer.parseInt(value));
                setter.accept(color);
                if (checkBox != null) {
                    checkBox.setSelected(true);
                }
                if (button != null) {
                    button.setEnabled(true);
                    button.setBackground(color);
                }
            } catch (NumberFormatException e) {
                // Invalid color, use default (null = region bg)
                setter.accept(null);
            }
        } else {
            // No custom color, use region background
            setter.accept(null);
            if (checkBox != null) {
                checkBox.setSelected(false);
            }
            if (button != null) {
                button.setEnabled(false);
                button.setBackground(Color.WHITE);
            }
        }
    }

    private void resetAllSettings() {
        if (hextraPainter == null) return;

        // Reset character text colors to defaults
        hextraPainter.setPrintableColor(Color.BLACK);
        hextraPainter.setNullByteColor(Color.RED);
        hextraPainter.setUnprintableColor(Color.BLUE);
        hextraPainter.setSpaceColor(Color.BLACK);

        // Reset region coloring to enabled
        hextraPainter.setRegionColoringEnabled(true);

        if (webSocketMode) {
            // Reset WS region colors to defaults
            hextraPainter.setWsKeyBg(new Color(255, 243, 179));
            hextraPainter.setWsStringBg(new Color(200, 245, 200));
            hextraPainter.setWsNumberBg(new Color(194, 229, 255));
            hextraPainter.setWsStructureBg(new Color(224, 224, 224));
            hextraPainter.setWsLiteralBg(new Color(229, 204, 255));
            hextraPainter.setWsBinaryBg(new Color(255, 204, 204));
            hextraPainter.setWsDefaultBg(Color.WHITE);
        } else {
            // Reset HTTP region background colors to defaults
            hextraPainter.setRequestLineBgColor(new Color(255, 245, 238));  // Seashell
            hextraPainter.setHeadersBgColor(new Color(240, 255, 240));      // Honeydew
            hextraPainter.setBodyBgColor(new Color(240, 248, 255));         // AliceBlue
            hextraPainter.setDefaultBgColor(Color.WHITE);
        }

        // Reset character background colors (null = use region background)
        hextraPainter.setPrintableBgColor(null);
        hextraPainter.setNullByteBgColor(null);
        hextraPainter.setUnprintableBgColor(null);
        hextraPainter.setSpaceBgColor(null);

        // Update UI buttons
        if (printableColorButton != null) printableColorButton.setBackground(Color.BLACK);
        if (nullByteColorButton != null) nullByteColorButton.setBackground(Color.RED);
        if (unprintableColorButton != null) unprintableColorButton.setBackground(Color.BLUE);
        if (spaceColorButton != null) spaceColorButton.setBackground(Color.BLACK);

        // Reset region coloring checkbox and buttons
        if (regionColoringCheckBox != null) {
            regionColoringCheckBox.setSelected(true);
        }
        if (webSocketMode) {
            if (wsKeyBgButton != null) { wsKeyBgButton.setEnabled(true); wsKeyBgButton.setBackground(new Color(255, 243, 179)); }
            if (wsStringBgButton != null) { wsStringBgButton.setEnabled(true); wsStringBgButton.setBackground(new Color(200, 245, 200)); }
            if (wsNumberBgButton != null) { wsNumberBgButton.setEnabled(true); wsNumberBgButton.setBackground(new Color(194, 229, 255)); }
            if (wsStructureBgButton != null) { wsStructureBgButton.setEnabled(true); wsStructureBgButton.setBackground(new Color(224, 224, 224)); }
            if (wsLiteralBgButton != null) { wsLiteralBgButton.setEnabled(true); wsLiteralBgButton.setBackground(new Color(229, 204, 255)); }
            if (wsBinaryBgButton != null) { wsBinaryBgButton.setEnabled(true); wsBinaryBgButton.setBackground(new Color(255, 204, 204)); }
            if (wsDefaultBgButton != null) { wsDefaultBgButton.setEnabled(true); wsDefaultBgButton.setBackground(Color.WHITE); }
        } else {
            if (requestLineBgButton != null) {
                requestLineBgButton.setEnabled(true);
                requestLineBgButton.setBackground(new Color(255, 245, 238));
            }
            if (headersBgButton != null) {
                headersBgButton.setEnabled(true);
                headersBgButton.setBackground(new Color(240, 255, 240));
            }
            if (bodyBgButton != null) {
                bodyBgButton.setEnabled(true);
                bodyBgButton.setBackground(new Color(240, 248, 255));
            }
            if (defaultBgButton != null) {
                defaultBgButton.setEnabled(true);
                defaultBgButton.setBackground(Color.WHITE);
            }
        }

        // Reset character background checkboxes and buttons
        if (printableBgCheckBox != null) {
            printableBgCheckBox.setSelected(false);
            printableBgButton.setEnabled(false);
            printableBgButton.setBackground(Color.WHITE);
        }
        if (nullByteBgCheckBox != null) {
            nullByteBgCheckBox.setSelected(false);
            nullByteBgButton.setEnabled(false);
            nullByteBgButton.setBackground(Color.WHITE);
        }
        if (unprintableBgCheckBox != null) {
            unprintableBgCheckBox.setSelected(false);
            unprintableBgButton.setEnabled(false);
            unprintableBgButton.setBackground(Color.WHITE);
        }
        if (spaceBgCheckBox != null) {
            spaceBgCheckBox.setSelected(false);
            spaceBgButton.setEnabled(false);
            spaceBgButton.setBackground(Color.WHITE);
        }

        // Clear persisted settings
        if (settingsManager != null) {
            settingsManager.saveSetting(SettingsManager.KEY_PRINTABLE_COLOR, null);
            settingsManager.saveSetting(SettingsManager.KEY_NULL_BYTE_COLOR, null);
            settingsManager.saveSetting(SettingsManager.KEY_UNPRINTABLE_COLOR, null);
            settingsManager.saveSetting(SettingsManager.KEY_PRINTABLE_BG, null);
            settingsManager.saveSetting(SettingsManager.KEY_NULL_BYTE_BG, null);
            settingsManager.saveSetting(SettingsManager.KEY_UNPRINTABLE_BG, null);
            settingsManager.saveSetting(SettingsManager.KEY_SPACE_BG, null);
            if (webSocketMode) {
                settingsManager.saveSetting(SettingsManager.KEY_WS_COLORING_ENABLED, null);
                settingsManager.saveSetting(SettingsManager.KEY_WS_KEY_BG, null);
                settingsManager.saveSetting(SettingsManager.KEY_WS_STRING_BG, null);
                settingsManager.saveSetting(SettingsManager.KEY_WS_NUMBER_BG, null);
                settingsManager.saveSetting(SettingsManager.KEY_WS_STRUCTURE_BG, null);
                settingsManager.saveSetting(SettingsManager.KEY_WS_LITERAL_BG, null);
                settingsManager.saveSetting(SettingsManager.KEY_WS_BINARY_BG, null);
                settingsManager.saveSetting(SettingsManager.KEY_WS_DEFAULT_BG, null);
            } else {
                settingsManager.saveSetting(SettingsManager.KEY_REGION_COLORING_ENABLED, null);
                settingsManager.saveSetting(SettingsManager.KEY_REQUEST_LINE_BG, null);
                settingsManager.saveSetting(SettingsManager.KEY_HEADERS_BG, null);
                settingsManager.saveSetting(SettingsManager.KEY_BODY_BG, null);
                settingsManager.saveSetting(SettingsManager.KEY_DEFAULT_BG, null);
            }
        }

        // Repaint
        if (codeArea != null) {
            codeArea.repaint();
        }

        // Reset theme combo to Light
        if (themeComboBox != null) {
            themeComboBox.setSelectedIndex(0);
        }
    }

    private void applySelectedTheme() {
        if (hextraPainter == null) return;

        String selectedTheme = themeComboBox != null ? (String) themeComboBox.getSelectedItem() : null;
        applyThemeByName(selectedTheme, true);
    }

    private void applyThemeByName(String themeName, boolean persistThemeName) {
        if (hextraPainter == null) return;
        if (themeName == null || "Custom".equals(themeName)) {
            // Custom means keep current colors (or UI not initialized yet).
            return;
        }

        ColorTheme theme;
        switch (themeName) {
            case "Dark":
                theme = ColorTheme.createDarkTheme();
                break;
            case "High Contrast":
                theme = ColorTheme.createHighContrastTheme();
                break;
            case "Monokai":
                theme = ColorTheme.createMonokaiTheme();
                break;
            case "Solarized Dark":
                theme = ColorTheme.createSolarizedDarkTheme();
                break;
            case "Solarized Light":
                theme = ColorTheme.createSolarizedLightTheme();
                break;
            case "Matrix":
                theme = ColorTheme.createMatrixTheme();
                break;
            case "Dracula":
                theme = ColorTheme.createDraculaTheme();
                break;
            case "Ocean":
                theme = ColorTheme.createOceanTheme();
                break;
            case "Retro":
                theme = ColorTheme.createRetroTheme();
                break;
            case "Light":
            default:
                theme = ColorTheme.createLightTheme();
                break;
        }

        applyTheme(theme);

        if (persistThemeName && settingsManager != null) {
            settingsManager.saveSetting(SettingsManager.KEY_CURRENT_THEME, themeName);
        }
    }

    private void applyTheme(ColorTheme theme) {
        if (hextraPainter == null || theme == null) return;

        // Apply text colors
        hextraPainter.setPrintableColor(theme.getPrintableColor());
        hextraPainter.setNullByteColor(theme.getNullByteColor());
        hextraPainter.setUnprintableColor(theme.getUnprintableColor());
        hextraPainter.setSpaceColor(theme.getSpaceColor());

        // Apply region background colors
        hextraPainter.setRequestLineBgColor(theme.getRequestLineBg());
        hextraPainter.setHeadersBgColor(theme.getHeadersBg());
        hextraPainter.setBodyBgColor(theme.getBodyBg());
        hextraPainter.setDefaultBgColor(theme.getDefaultBg());

        // Apply character background colors
        hextraPainter.setPrintableBgColor(theme.getPrintableBg());
        hextraPainter.setNullByteBgColor(theme.getNullByteBg());
        hextraPainter.setUnprintableBgColor(theme.getUnprintableBg());
        hextraPainter.setSpaceBgColor(theme.getSpaceBg());

        // Update UI buttons
        updateColorButtons(theme);

        // Persist colors
        saveAllColors();

        // Repaint
        if (codeArea != null) {
            codeArea.repaint();
        }
    }

    private void updateColorButtons(ColorTheme theme) {
        if (printableColorButton != null) printableColorButton.setBackground(theme.getPrintableColor());
        if (nullByteColorButton != null) nullByteColorButton.setBackground(theme.getNullByteColor());
        if (unprintableColorButton != null) unprintableColorButton.setBackground(theme.getUnprintableColor());
        if (spaceColorButton != null) spaceColorButton.setBackground(theme.getSpaceColor());

        if (requestLineBgButton != null) requestLineBgButton.setBackground(theme.getRequestLineBg());
        if (headersBgButton != null) headersBgButton.setBackground(theme.getHeadersBg());
        if (bodyBgButton != null) bodyBgButton.setBackground(theme.getBodyBg());
        if (defaultBgButton != null) defaultBgButton.setBackground(theme.getDefaultBg());

        // Character background buttons/checkboxes
        updateCharBgButton(theme.getPrintableBg(), printableBgCheckBox, printableBgButton);
        updateCharBgButton(theme.getNullByteBg(), nullByteBgCheckBox, nullByteBgButton);
        updateCharBgButton(theme.getUnprintableBg(), unprintableBgCheckBox, unprintableBgButton);
        updateCharBgButton(theme.getSpaceBg(), spaceBgCheckBox, spaceBgButton);
    }

    private void updateCharBgButton(Color color, javax.swing.JCheckBox checkBox, JButton button) {
        if (checkBox == null || button == null) return;
        if (color != null) {
            checkBox.setSelected(true);
            button.setEnabled(true);
            button.setBackground(color);
        } else {
            checkBox.setSelected(false);
            button.setEnabled(false);
            button.setBackground(Color.WHITE);
        }
    }

    private void saveAllColors() {
        if (settingsManager == null || hextraPainter == null) return;

        settingsManager.saveColor(SettingsManager.KEY_PRINTABLE_COLOR, hextraPainter.getPrintableColor());
        settingsManager.saveColor(SettingsManager.KEY_NULL_BYTE_COLOR, hextraPainter.getNullByteColor());
        settingsManager.saveColor(SettingsManager.KEY_UNPRINTABLE_COLOR, hextraPainter.getUnprintableColor());
        settingsManager.saveColor(SettingsManager.KEY_SPACE_COLOR, hextraPainter.getSpaceColor());

        settingsManager.saveColor(SettingsManager.KEY_REQUEST_LINE_BG, hextraPainter.getRequestLineBgColor());
        settingsManager.saveColor(SettingsManager.KEY_HEADERS_BG, hextraPainter.getHeadersBgColor());
        settingsManager.saveColor(SettingsManager.KEY_BODY_BG, hextraPainter.getBodyBgColor());
        settingsManager.saveColor(SettingsManager.KEY_DEFAULT_BG, hextraPainter.getDefaultBgColor());

        // Character backgrounds - save as color RGB or clear if null
        saveCharBgColor(SettingsManager.KEY_PRINTABLE_BG, hextraPainter.getPrintableBgColor());
        saveCharBgColor(SettingsManager.KEY_NULL_BYTE_BG, hextraPainter.getNullByteBgColor());
        saveCharBgColor(SettingsManager.KEY_UNPRINTABLE_BG, hextraPainter.getUnprintableBgColor());
        saveCharBgColor(SettingsManager.KEY_SPACE_BG, hextraPainter.getSpaceBgColor());
    }

    private void saveCharBgColor(String key, Color color) {
        if (settingsManager == null) return;
        if (color != null) {
            settingsManager.saveColor(key, color);
        } else {
            settingsManager.clearSetting(key);
        }
    }

    /**
     * This method is called from within the constructor to initialize the form.
     * WARNING: Do NOT modify this code. The content of this method is always
     * regenerated by the Form Editor.
     */
    @SuppressWarnings("unchecked")
    // <editor-fold defaultstate="collapsed" desc="Generated Code">//GEN-BEGIN:initComponents
    private void initComponents() {

        modePanel = new javax.swing.JPanel();
        viewModeScrollModeLabel = new javax.swing.JLabel();
        viewModeComboBox = new javax.swing.JComboBox<>();
        charRenderingScrollModeLabel = new javax.swing.JLabel();
        charRenderingComboBox = new javax.swing.JComboBox<>();
        charAntialiasingScrollModeLabel = new javax.swing.JLabel();
        charAntialiasingComboBox = new javax.swing.JComboBox<>();
        codeTypeScrollModeLabel = new javax.swing.JLabel();
        codeTypeComboBox = new javax.swing.JComboBox<>();
        editationAllowedLabel = new javax.swing.JLabel();
        editationAllowedComboBox = new javax.swing.JComboBox<>();
        fontPanel = new javax.swing.JPanel();
        fontFamilyLabel = new javax.swing.JLabel();
        fontFamilyComboBox = new javax.swing.JComboBox<>();
        fontSizeLabel = new javax.swing.JLabel();
        fontSizeComboBox = new javax.swing.JComboBox<>();
        charsetLabel = new javax.swing.JLabel();
        charsetComboBox = new javax.swing.JComboBox<>();
        showNonprintableCharactersCheckBox = new javax.swing.JCheckBox();
        statePanel = new javax.swing.JPanel();
        dataSizeLabel = new javax.swing.JLabel();
        dataSizeTextField = new javax.swing.JTextField();
        loadDataButton = new javax.swing.JButton();
        saveDataButton = new javax.swing.JButton();
        positionPanel = new javax.swing.JPanel();
        positionLabel = new javax.swing.JLabel();
        positionTextField = new javax.swing.JTextField();
        codeOffsetLabel = new javax.swing.JLabel();
        codeOffsetTextField = new javax.swing.JTextField();
        activeSectionLabel = new javax.swing.JLabel();
        activeSectionComboBox = new javax.swing.JComboBox<>();
        selectionPanel = new javax.swing.JPanel();
        selectionStartLabel = new javax.swing.JLabel();
        selectionStartTextField = new javax.swing.JTextField();
        selectionEndLabel = new javax.swing.JLabel();
        selectionEndTextField = new javax.swing.JTextField();
        layoutPanel = new javax.swing.JPanel();
        lineLengthLabel = new javax.swing.JLabel();
        lineLengthSpinner = new javax.swing.JSpinner();
        lineNumbersPanel = new javax.swing.JPanel();
        showLineNumbersCheckBox = new javax.swing.JCheckBox();
        lineNumbersLengthLabel = new javax.swing.JLabel();
        lineNumbersLengthComboBox = new javax.swing.JComboBox<>();
        lineNumbersLengthSpinner = new javax.swing.JSpinner();
        lineNumbersSpaceLabel = new javax.swing.JLabel();
        lineNumbersSpaceComboBox = new javax.swing.JComboBox<>();
        lineNumbersSpaceSpinner = new javax.swing.JSpinner();
        wrapLineModeCheckBox = new javax.swing.JCheckBox();
        headerPanel = new javax.swing.JPanel();
        showHeaderCheckBox = new javax.swing.JCheckBox();
        headerSpaceLabel = new javax.swing.JLabel();
        headerSpaceComboBox = new javax.swing.JComboBox<>();
        headerSpaceSpinner = new javax.swing.JSpinner();
        byteGroupSizeLabel = new javax.swing.JLabel();
        byteGroupSizeSpinner = new javax.swing.JSpinner();
        spaceGroupSizeLabel = new javax.swing.JLabel();
        spaceGroupSizeSpinner = new javax.swing.JSpinner();
        decorationPanel = new javax.swing.JPanel();
        backgroundModeLabel = new javax.swing.JLabel();
        backgroundModeComboBox = new javax.swing.JComboBox<>();
        lineNumbersBackgroundCheckBox = new javax.swing.JCheckBox();
        linesPanel = new javax.swing.JPanel();
        decoratorLineNumLineCheckBox = new javax.swing.JCheckBox();
        decoratorSplitLineCheckBox = new javax.swing.JCheckBox();
        decoratorBoxCheckBox = new javax.swing.JCheckBox();
        decoratorHeaderLineCheckBox = new javax.swing.JCheckBox();
        borderTypeLabel = new javax.swing.JLabel();
        borderTypeComboBox = new javax.swing.JComboBox<>();
        hexCharactersModeLabel = new javax.swing.JLabel();
        hexCharactersModeComboBox = new javax.swing.JComboBox<>();
        positionCodeTypeLabel = new javax.swing.JLabel();
        positionCodeTypeComboBox = new javax.swing.JComboBox<>();
        scrollingPanel = new javax.swing.JPanel();
        verticalPanel = new javax.swing.JPanel();
        verticalScrollBarVisibilityModeLabel = new javax.swing.JLabel();
        verticalScrollBarVisibilityComboBox = new javax.swing.JComboBox<>();
        verticalScrollModeLabel = new javax.swing.JLabel();
        verticalScrollModeComboBox = new javax.swing.JComboBox<>();
        verticalPositionLabel = new javax.swing.JLabel();
        verticalPositionTextField = new javax.swing.JTextField();
        horizontalPanel = new javax.swing.JPanel();
        horizontalScrollBarVisibilityLabel = new javax.swing.JLabel();
        horizontalScrollBarVisibilityComboBox = new javax.swing.JComboBox<>();
        horizontalScrollModeLabel = new javax.swing.JLabel();
        horizontalScrollModeComboBox = new javax.swing.JComboBox<>();
        horizontalPositionLabel = new javax.swing.JLabel();
        horizontalPositionTextField = new javax.swing.JTextField();
        horizontalByteShiftLabel = new javax.swing.JLabel();
        horizontalByteShiftTextField = new javax.swing.JTextField();
        cursorPanel = new javax.swing.JPanel();
        showShadowCursorCheckBox = new javax.swing.JCheckBox();
        cursorRenderingModeLabel = new javax.swing.JLabel();
        cursorRenderingModeComboBox = new javax.swing.JComboBox<>();
        cursorInsertShapeModeLabel = new javax.swing.JLabel();
        cursorInsertShapeComboBox = new javax.swing.JComboBox<>();
        cursorOverwriteShapeModeLabel = new javax.swing.JLabel();
        cursorOverwriteShapeComboBox = new javax.swing.JComboBox<>();
        cursorBlinkingRateLabel = new javax.swing.JLabel();
        cursorBlinkingRateSpinner = new javax.swing.JSpinner();
        splitPane = new javax.swing.JSplitPane();
        tabbedPane = new javax.swing.JTabbedPane();
        modeTab = new javax.swing.JPanel();
        stateTab = new javax.swing.JPanel();
        layoutTab = new javax.swing.JPanel();
        decorationTab = new javax.swing.JPanel();
        scrollingTab = new javax.swing.JPanel();
        cursorTab = new javax.swing.JPanel();

        viewModeScrollModeLabel.setText("View Mode");

        viewModeComboBox.setModel(new javax.swing.DefaultComboBoxModel<>(new String[] { "DUAL", "HEXADECIMAL", "PREVIEW" }));
        viewModeComboBox.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                viewModeComboBoxActionPerformed(evt);
            }
        });

        charRenderingScrollModeLabel.setText("Character Rendering");

        charRenderingComboBox.setModel(new javax.swing.DefaultComboBoxModel<>(new String[] { "AUTO", "LINE_AT_ONCE", "TOP_LEFT", "CENTER" }));
        charRenderingComboBox.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                charRenderingComboBoxActionPerformed(evt);
            }
        });

        charAntialiasingScrollModeLabel.setText("Character Antialiasing");

        charAntialiasingComboBox.setModel(new javax.swing.DefaultComboBoxModel<>(new String[] { "OFF", "AUTO", "DEFAULT", "BASIC", "GASP", "LCD_HRGB", "LCD_HBGR", "LCD_VRGB", "LCD_VBGR" }));
        charAntialiasingComboBox.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                charAntialiasingComboBoxActionPerformed(evt);
            }
        });

        codeTypeScrollModeLabel.setText("Code Type");

        codeTypeComboBox.setModel(new javax.swing.DefaultComboBoxModel<>(new String[] { "BINARY", "OCTAL", "DECIMAL", "HEXADECIMAL" }));
        codeTypeComboBox.setSelectedIndex(3);
        codeTypeComboBox.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                codeTypeComboBoxActionPerformed(evt);
            }
        });

        editationAllowedLabel.setText("Editation");

        editationAllowedComboBox.setModel(new javax.swing.DefaultComboBoxModel<>(new String[] { "READ_ONLY", "OVERWRITE_ONLY", "ALLOWED" }));
        editationAllowedComboBox.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                editationAllowedComboBoxActionPerformed(evt);
            }
        });

        fontPanel.setBorder(javax.swing.BorderFactory.createTitledBorder("Font"));

        fontFamilyLabel.setText("Font Family");

        fontFamilyComboBox.setModel(new javax.swing.DefaultComboBoxModel<>(new String[] { "DIALOG", "MONOSPACE", "SERIF" }));
        fontFamilyComboBox.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                fontFamilyComboBoxActionPerformed(evt);
            }
        });

        fontSizeLabel.setText("Font Size");

        fontSizeComboBox.setModel(new javax.swing.DefaultComboBoxModel<>(new String[] { "8", "9", "10", "12", "14", "18", "22" }));
        fontSizeComboBox.setSelectedIndex(3);
        fontSizeComboBox.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                fontSizeComboBoxActionPerformed(evt);
            }
        });

        javax.swing.GroupLayout fontPanelLayout = new javax.swing.GroupLayout(fontPanel);
        fontPanel.setLayout(fontPanelLayout);
        fontPanelLayout.setHorizontalGroup(
            fontPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(fontPanelLayout.createSequentialGroup()
                .addContainerGap()
                .addGroup(fontPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addComponent(fontFamilyComboBox, 0, 264, Short.MAX_VALUE)
                    .addComponent(fontSizeComboBox, 0, 264, Short.MAX_VALUE)
                    .addGroup(fontPanelLayout.createSequentialGroup()
                        .addGroup(fontPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                            .addComponent(fontFamilyLabel)
                            .addComponent(fontSizeLabel))
                        .addGap(0, 0, Short.MAX_VALUE)))
                .addContainerGap())
        );
        fontPanelLayout.setVerticalGroup(
            fontPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(fontPanelLayout.createSequentialGroup()
                .addContainerGap()
                .addComponent(fontFamilyLabel)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(fontFamilyComboBox, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(fontSizeLabel)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(fontSizeComboBox, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addContainerGap(javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
        );

        charsetLabel.setText("Charset");

        charsetComboBox.setModel(new javax.swing.DefaultComboBoxModel<>(new String[] { "UTF-8", "UTF-16", "UTF-16BE", "US-ASCII", "IBM852", "ISO-8859-1" }));
        charsetComboBox.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                charsetComboBoxActionPerformed(evt);
            }
        });

        showNonprintableCharactersCheckBox.setText("Show Nonprintable Characters");
        showNonprintableCharactersCheckBox.addItemListener(new java.awt.event.ItemListener() {
            public void itemStateChanged(java.awt.event.ItemEvent evt) {
                showNonprintableCharactersCheckBoxItemStateChanged(evt);
            }
        });

        javax.swing.GroupLayout modePanelLayout = new javax.swing.GroupLayout(modePanel);
        modePanel.setLayout(modePanelLayout);
        modePanelLayout.setHorizontalGroup(
            modePanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(modePanelLayout.createSequentialGroup()
                .addContainerGap()
                .addGroup(modePanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addComponent(viewModeComboBox, 0, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                    .addComponent(showNonprintableCharactersCheckBox, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                    .addComponent(charRenderingComboBox, 0, 286, Short.MAX_VALUE)
                    .addComponent(codeTypeComboBox, 0, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                    .addComponent(charAntialiasingComboBox, 0, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                    .addComponent(editationAllowedComboBox, 0, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                    .addComponent(fontPanel, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                    .addComponent(charsetComboBox, 0, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                    .addGroup(modePanelLayout.createSequentialGroup()
                        .addGroup(modePanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                            .addComponent(viewModeScrollModeLabel)
                            .addComponent(charRenderingScrollModeLabel)
                            .addComponent(charAntialiasingScrollModeLabel)
                            .addComponent(codeTypeScrollModeLabel)
                            .addComponent(editationAllowedLabel)
                            .addComponent(charsetLabel))
                        .addGap(0, 0, Short.MAX_VALUE)))
                .addContainerGap())
        );
        modePanelLayout.setVerticalGroup(
            modePanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(modePanelLayout.createSequentialGroup()
                .addContainerGap()
                .addComponent(viewModeScrollModeLabel)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(viewModeComboBox, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(showNonprintableCharactersCheckBox)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(codeTypeScrollModeLabel)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(codeTypeComboBox, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(charRenderingScrollModeLabel)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(charRenderingComboBox, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(charAntialiasingScrollModeLabel)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(charAntialiasingComboBox, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(editationAllowedLabel)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(editationAllowedComboBox, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(fontPanel, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(charsetLabel)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(charsetComboBox, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addContainerGap(27, Short.MAX_VALUE))
        );

        dataSizeLabel.setText("Data Size");

        dataSizeTextField.setEditable(false);
        dataSizeTextField.setText("0");

        loadDataButton.setText("Load...");
        loadDataButton.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                loadDataButtonActionPerformed(evt);
            }
        });

        saveDataButton.setText("Save...");
        saveDataButton.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                saveDataButtonActionPerformed(evt);
            }
        });

        positionPanel.setBorder(javax.swing.BorderFactory.createTitledBorder("Position"));

        positionLabel.setText("Data Position");

        positionTextField.setEditable(false);

        codeOffsetLabel.setText("Code Offset Position");

        codeOffsetTextField.setEditable(false);

        activeSectionLabel.setText("Active Section");

        activeSectionComboBox.setModel(new javax.swing.DefaultComboBoxModel<>(new String[] { "CODE_MATRIX", "TEXT_PREVIEW" }));
        activeSectionComboBox.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                activeSectionComboBoxActionPerformed(evt);
            }
        });

        javax.swing.GroupLayout positionPanelLayout = new javax.swing.GroupLayout(positionPanel);
        positionPanel.setLayout(positionPanelLayout);
        positionPanelLayout.setHorizontalGroup(
            positionPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(positionPanelLayout.createSequentialGroup()
                .addContainerGap()
                .addGroup(positionPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addComponent(codeOffsetTextField)
                    .addComponent(positionTextField)
                    .addGroup(positionPanelLayout.createSequentialGroup()
                        .addGroup(positionPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                            .addComponent(positionLabel)
                            .addComponent(codeOffsetLabel)
                            .addComponent(activeSectionLabel))
                        .addGap(0, 94, Short.MAX_VALUE))
                    .addComponent(activeSectionComboBox, 0, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
                .addContainerGap())
        );
        positionPanelLayout.setVerticalGroup(
            positionPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(positionPanelLayout.createSequentialGroup()
                .addContainerGap()
                .addComponent(positionLabel)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(positionTextField, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(codeOffsetLabel, javax.swing.GroupLayout.PREFERRED_SIZE, 15, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(codeOffsetTextField, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(activeSectionLabel)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(activeSectionComboBox, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addContainerGap(javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
        );

        selectionPanel.setBorder(javax.swing.BorderFactory.createTitledBorder("Selection"));

        selectionStartLabel.setText("Selection Start");

        selectionStartTextField.setEditable(false);

        selectionEndLabel.setText("Selection End");

        selectionEndTextField.setEditable(false);

        javax.swing.GroupLayout selectionPanelLayout = new javax.swing.GroupLayout(selectionPanel);
        selectionPanel.setLayout(selectionPanelLayout);
        selectionPanelLayout.setHorizontalGroup(
            selectionPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(selectionPanelLayout.createSequentialGroup()
                .addContainerGap()
                .addGroup(selectionPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.TRAILING)
                    .addComponent(selectionEndTextField, javax.swing.GroupLayout.Alignment.LEADING)
                    .addComponent(selectionStartTextField, javax.swing.GroupLayout.Alignment.LEADING)
                    .addGroup(javax.swing.GroupLayout.Alignment.LEADING, selectionPanelLayout.createSequentialGroup()
                        .addGroup(selectionPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                            .addComponent(selectionEndLabel)
                            .addComponent(selectionStartLabel))
                        .addGap(0, 0, Short.MAX_VALUE)))
                .addContainerGap())
        );
        selectionPanelLayout.setVerticalGroup(
            selectionPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(selectionPanelLayout.createSequentialGroup()
                .addContainerGap()
                .addComponent(selectionStartLabel)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(selectionStartTextField, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(selectionEndLabel)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(selectionEndTextField, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addContainerGap(javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
        );

        javax.swing.GroupLayout statePanelLayout = new javax.swing.GroupLayout(statePanel);
        statePanel.setLayout(statePanelLayout);
        statePanelLayout.setHorizontalGroup(
            statePanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(javax.swing.GroupLayout.Alignment.TRAILING, statePanelLayout.createSequentialGroup()
                .addContainerGap()
                .addGroup(statePanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.TRAILING)
                    .addComponent(selectionPanel, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                    .addComponent(positionPanel, javax.swing.GroupLayout.Alignment.LEADING, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                    .addComponent(dataSizeTextField, javax.swing.GroupLayout.Alignment.LEADING)
                    .addGroup(javax.swing.GroupLayout.Alignment.LEADING, statePanelLayout.createSequentialGroup()
                        .addGroup(statePanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                            .addComponent(dataSizeLabel)
                            .addGroup(statePanelLayout.createSequentialGroup()
                                .addComponent(loadDataButton)
                                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                                .addComponent(saveDataButton)))
                        .addGap(0, 0, Short.MAX_VALUE)))
                .addContainerGap())
        );
        statePanelLayout.setVerticalGroup(
            statePanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(statePanelLayout.createSequentialGroup()
                .addGap(9, 9, 9)
                .addComponent(dataSizeLabel)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(dataSizeTextField, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addGap(7, 7, 7)
                .addGroup(statePanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(loadDataButton)
                    .addComponent(saveDataButton))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(positionPanel, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(selectionPanel, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addContainerGap(94, Short.MAX_VALUE))
        );

        lineLengthLabel.setText("Bytes Per Line");

        lineLengthSpinner.setModel(new javax.swing.SpinnerNumberModel(16, 1, null, 1));
        lineLengthSpinner.addChangeListener(new javax.swing.event.ChangeListener() {
            public void stateChanged(javax.swing.event.ChangeEvent evt) {
                lineLengthSpinnerStateChanged(evt);
            }
        });

        lineNumbersPanel.setBorder(javax.swing.BorderFactory.createTitledBorder("Line Numbers"));

        showLineNumbersCheckBox.setText("Show Line Numbers");
        showLineNumbersCheckBox.addItemListener(new java.awt.event.ItemListener() {
            public void itemStateChanged(java.awt.event.ItemEvent evt) {
                showLineNumbersCheckBoxItemStateChanged(evt);
            }
        });

        lineNumbersLengthLabel.setText("Line Numbers Length");

        lineNumbersLengthComboBox.setModel(new javax.swing.DefaultComboBoxModel<>(new String[] { "AUTO", "SPECIFIED" }));
        lineNumbersLengthComboBox.setSelectedIndex(1);
        lineNumbersLengthComboBox.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                lineNumbersLengthComboBoxActionPerformed(evt);
            }
        });

        lineNumbersLengthSpinner.setModel(new javax.swing.SpinnerNumberModel(0, 0, null, 1));
        lineNumbersLengthSpinner.setValue(8);
        lineNumbersLengthSpinner.addChangeListener(new javax.swing.event.ChangeListener() {
            public void stateChanged(javax.swing.event.ChangeEvent evt) {
                lineNumbersLengthSpinnerStateChanged(evt);
            }
        });

        lineNumbersSpaceLabel.setText("Line Numbers Space");

        lineNumbersSpaceComboBox.setModel(new javax.swing.DefaultComboBoxModel<>(new String[] { "NONE", "SPECIFIED", "QUARTER_UNIT", "HALF_UNIT", "ONE_UNIT", "ONE_AND_HALF_UNIT", "DOUBLE_UNIT" }));
        lineNumbersSpaceComboBox.setSelectedIndex(4);
        lineNumbersSpaceComboBox.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                lineNumbersSpaceComboBoxActionPerformed(evt);
            }
        });

        lineNumbersSpaceSpinner.setModel(new javax.swing.SpinnerNumberModel(0, 0, null, 1));
        lineNumbersSpaceSpinner.addChangeListener(new javax.swing.event.ChangeListener() {
            public void stateChanged(javax.swing.event.ChangeEvent evt) {
                lineNumbersSpaceSpinnerStateChanged(evt);
            }
        });

        javax.swing.GroupLayout lineNumbersPanelLayout = new javax.swing.GroupLayout(lineNumbersPanel);
        lineNumbersPanel.setLayout(lineNumbersPanelLayout);
        lineNumbersPanelLayout.setHorizontalGroup(
            lineNumbersPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(lineNumbersPanelLayout.createSequentialGroup()
                .addComponent(showLineNumbersCheckBox)
                .addGap(0, 0, Short.MAX_VALUE))
            .addGroup(lineNumbersPanelLayout.createSequentialGroup()
                .addContainerGap()
                .addGroup(lineNumbersPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addGroup(lineNumbersPanelLayout.createSequentialGroup()
                        .addComponent(lineNumbersLengthComboBox, javax.swing.GroupLayout.PREFERRED_SIZE, 140, javax.swing.GroupLayout.PREFERRED_SIZE)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                        .addComponent(lineNumbersLengthSpinner))
                    .addGroup(lineNumbersPanelLayout.createSequentialGroup()
                        .addGroup(lineNumbersPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                            .addComponent(lineNumbersLengthLabel)
                            .addComponent(lineNumbersSpaceLabel))
                        .addGap(0, 0, Short.MAX_VALUE))
                    .addGroup(lineNumbersPanelLayout.createSequentialGroup()
                        .addComponent(lineNumbersSpaceComboBox, javax.swing.GroupLayout.PREFERRED_SIZE, 140, javax.swing.GroupLayout.PREFERRED_SIZE)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                        .addComponent(lineNumbersSpaceSpinner)))
                .addContainerGap())
        );
        lineNumbersPanelLayout.setVerticalGroup(
            lineNumbersPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(lineNumbersPanelLayout.createSequentialGroup()
                .addComponent(showLineNumbersCheckBox)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(lineNumbersLengthLabel)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addGroup(lineNumbersPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(lineNumbersLengthComboBox, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addComponent(lineNumbersLengthSpinner, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(lineNumbersSpaceLabel)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addGroup(lineNumbersPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(lineNumbersSpaceComboBox, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addComponent(lineNumbersSpaceSpinner, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE))
                .addContainerGap(javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
        );

        wrapLineModeCheckBox.setText("Wrap Line Mode");
        wrapLineModeCheckBox.addItemListener(new java.awt.event.ItemListener() {
            public void itemStateChanged(java.awt.event.ItemEvent evt) {
                wrapLineModeCheckBoxItemStateChanged(evt);
            }
        });

        headerPanel.setBorder(javax.swing.BorderFactory.createTitledBorder("Header"));

        showHeaderCheckBox.setText("Show Header");
        showHeaderCheckBox.addItemListener(new java.awt.event.ItemListener() {
            public void itemStateChanged(java.awt.event.ItemEvent evt) {
                showHeaderCheckBoxItemStateChanged(evt);
            }
        });

        headerSpaceLabel.setText("Header Space");

        headerSpaceComboBox.setModel(new javax.swing.DefaultComboBoxModel<>(new String[] { "NONE", "SPECIFIED", "QUARTER_UNIT", "HALF_UNIT", "ONE_UNIT", "ONE_AND_HALF_UNIT", "DOUBLE_UNIT" }));
        headerSpaceComboBox.setSelectedIndex(2);
        headerSpaceComboBox.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                headerSpaceComboBoxActionPerformed(evt);
            }
        });

        headerSpaceSpinner.setModel(new javax.swing.SpinnerNumberModel(0, 0, null, 1));
        headerSpaceSpinner.addChangeListener(new javax.swing.event.ChangeListener() {
            public void stateChanged(javax.swing.event.ChangeEvent evt) {
                headerSpaceSpinnerStateChanged(evt);
            }
        });

        javax.swing.GroupLayout headerPanelLayout = new javax.swing.GroupLayout(headerPanel);
        headerPanel.setLayout(headerPanelLayout);
        headerPanelLayout.setHorizontalGroup(
            headerPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(headerPanelLayout.createSequentialGroup()
                .addContainerGap()
                .addGroup(headerPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addGroup(headerPanelLayout.createSequentialGroup()
                        .addComponent(headerSpaceComboBox, javax.swing.GroupLayout.PREFERRED_SIZE, 140, javax.swing.GroupLayout.PREFERRED_SIZE)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                        .addComponent(headerSpaceSpinner, javax.swing.GroupLayout.DEFAULT_SIZE, 317, Short.MAX_VALUE))
                    .addGroup(headerPanelLayout.createSequentialGroup()
                        .addGroup(headerPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                            .addComponent(showHeaderCheckBox)
                            .addComponent(headerSpaceLabel))
                        .addGap(0, 0, Short.MAX_VALUE)))
                .addContainerGap())
        );
        headerPanelLayout.setVerticalGroup(
            headerPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(headerPanelLayout.createSequentialGroup()
                .addComponent(showHeaderCheckBox)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(headerSpaceLabel)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addGroup(headerPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(headerSpaceComboBox, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addComponent(headerSpaceSpinner, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE))
                .addContainerGap(javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
        );

        byteGroupSizeLabel.setText("Byte Group Size");

        byteGroupSizeSpinner.setModel(new javax.swing.SpinnerNumberModel(0, 0, null, 1));
        byteGroupSizeSpinner.addChangeListener(new javax.swing.event.ChangeListener() {
            public void stateChanged(javax.swing.event.ChangeEvent evt) {
                byteGroupSizeSpinnerStateChanged(evt);
            }
        });

        spaceGroupSizeLabel.setText("Space Group Size");

        spaceGroupSizeSpinner.setModel(new javax.swing.SpinnerNumberModel(0, 0, null, 1));
        spaceGroupSizeSpinner.addChangeListener(new javax.swing.event.ChangeListener() {
            public void stateChanged(javax.swing.event.ChangeEvent evt) {
                spaceGroupSizeSpinnerStateChanged(evt);
            }
        });

        javax.swing.GroupLayout layoutPanelLayout = new javax.swing.GroupLayout(layoutPanel);
        layoutPanel.setLayout(layoutPanelLayout);
        layoutPanelLayout.setHorizontalGroup(
            layoutPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(layoutPanelLayout.createSequentialGroup()
                .addContainerGap()
                .addGroup(layoutPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addGroup(layoutPanelLayout.createSequentialGroup()
                        .addGroup(layoutPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                            .addComponent(lineLengthLabel)
                            .addComponent(wrapLineModeCheckBox))
                        .addGap(0, 0, Short.MAX_VALUE))
                    .addGroup(javax.swing.GroupLayout.Alignment.TRAILING, layoutPanelLayout.createSequentialGroup()
                        .addGroup(layoutPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.TRAILING)
                            .addComponent(spaceGroupSizeSpinner, javax.swing.GroupLayout.Alignment.LEADING)
                            .addComponent(byteGroupSizeSpinner, javax.swing.GroupLayout.Alignment.LEADING)
                            .addComponent(headerPanel, javax.swing.GroupLayout.Alignment.LEADING, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                            .addComponent(lineLengthSpinner, javax.swing.GroupLayout.Alignment.LEADING)
                            .addComponent(lineNumbersPanel, javax.swing.GroupLayout.Alignment.LEADING, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                            .addGroup(javax.swing.GroupLayout.Alignment.LEADING, layoutPanelLayout.createSequentialGroup()
                                .addGroup(layoutPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.TRAILING)
                                    .addComponent(byteGroupSizeLabel, javax.swing.GroupLayout.Alignment.LEADING)
                                    .addComponent(spaceGroupSizeLabel, javax.swing.GroupLayout.Alignment.LEADING))
                                .addGap(0, 0, Short.MAX_VALUE)))
                        .addContainerGap())))
        );
        layoutPanelLayout.setVerticalGroup(
            layoutPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(layoutPanelLayout.createSequentialGroup()
                .addContainerGap()
                .addComponent(wrapLineModeCheckBox)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(lineLengthLabel)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(lineLengthSpinner, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(headerPanel, javax.swing.GroupLayout.PREFERRED_SIZE, 104, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(lineNumbersPanel, javax.swing.GroupLayout.PREFERRED_SIZE, 156, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(byteGroupSizeLabel)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(byteGroupSizeSpinner, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(spaceGroupSizeLabel)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(spaceGroupSizeSpinner, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addContainerGap(87, Short.MAX_VALUE))
        );

        backgroundModeLabel.setText("Background Mode");

        backgroundModeComboBox.setModel(new javax.swing.DefaultComboBoxModel<>(new String[] { "NONE", "PLAIN", "STRIPPED", "GRIDDED" }));
        backgroundModeComboBox.setSelectedIndex(2);
        backgroundModeComboBox.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                backgroundModeComboBoxActionPerformed(evt);
            }
        });

        lineNumbersBackgroundCheckBox.setText("Include Line Numbers");
        lineNumbersBackgroundCheckBox.addItemListener(new java.awt.event.ItemListener() {
            public void itemStateChanged(java.awt.event.ItemEvent evt) {
                lineNumbersBackgroundCheckBoxItemStateChanged(evt);
            }
        });

        linesPanel.setBorder(javax.swing.BorderFactory.createTitledBorder("Lines"));

        decoratorLineNumLineCheckBox.setText("LineNum Line");
        decoratorLineNumLineCheckBox.addItemListener(new java.awt.event.ItemListener() {
            public void itemStateChanged(java.awt.event.ItemEvent evt) {
                decoratorLineNumLineCheckBoxItemStateChanged(evt);
            }
        });

        decoratorSplitLineCheckBox.setText("Split Line");
        decoratorSplitLineCheckBox.addItemListener(new java.awt.event.ItemListener() {
            public void itemStateChanged(java.awt.event.ItemEvent evt) {
                decoratorSplitLineCheckBoxItemStateChanged(evt);
            }
        });

        decoratorBoxCheckBox.setText("Area Box");
        decoratorBoxCheckBox.addItemListener(new java.awt.event.ItemListener() {
            public void itemStateChanged(java.awt.event.ItemEvent evt) {
                decoratorBoxCheckBoxItemStateChanged(evt);
            }
        });

        decoratorHeaderLineCheckBox.setText("Header Line");
        decoratorHeaderLineCheckBox.addItemListener(new java.awt.event.ItemListener() {
            public void itemStateChanged(java.awt.event.ItemEvent evt) {
                decoratorHeaderLineCheckBoxItemStateChanged(evt);
            }
        });

        javax.swing.GroupLayout linesPanelLayout = new javax.swing.GroupLayout(linesPanel);
        linesPanel.setLayout(linesPanelLayout);
        linesPanelLayout.setHorizontalGroup(
            linesPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(linesPanelLayout.createSequentialGroup()
                .addContainerGap()
                .addGroup(linesPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addComponent(decoratorLineNumLineCheckBox, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                    .addComponent(decoratorSplitLineCheckBox, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                    .addComponent(decoratorBoxCheckBox, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                    .addComponent(decoratorHeaderLineCheckBox, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
                .addContainerGap())
        );
        linesPanelLayout.setVerticalGroup(
            linesPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(linesPanelLayout.createSequentialGroup()
                .addComponent(decoratorHeaderLineCheckBox)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(decoratorLineNumLineCheckBox)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(decoratorSplitLineCheckBox)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(decoratorBoxCheckBox))
        );

        borderTypeLabel.setText("Border Type");

        borderTypeComboBox.setModel(new javax.swing.DefaultComboBoxModel<>(new String[] { "NONE", "EMPTY BORDER", "MARGIN BORDER", "BEVEL BORDER - RAISED", "BEVEL BORDER - LOWERED", "ETCHED BORDER - RAISED", "ETCHED BORDER - LOWERED", "LINE BORDER" }));
        borderTypeComboBox.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                borderTypeComboBoxActionPerformed(evt);
            }
        });

        hexCharactersModeLabel.setText("Hex Chars Mode");

        hexCharactersModeComboBox.setModel(new javax.swing.DefaultComboBoxModel<>(new String[] { "LOWER", "UPPER" }));
        hexCharactersModeComboBox.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                hexCharactersModeComboBoxActionPerformed(evt);
            }
        });

        positionCodeTypeLabel.setText("Position Code Type");

        positionCodeTypeComboBox.setModel(new javax.swing.DefaultComboBoxModel<>(new String[] { "OCTAL", "DECIMAL", "HEXADECIMAL" }));
        positionCodeTypeComboBox.setSelectedIndex(2);
        positionCodeTypeComboBox.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                positionCodeTypeComboBoxActionPerformed(evt);
            }
        });

        javax.swing.GroupLayout decorationPanelLayout = new javax.swing.GroupLayout(decorationPanel);
        decorationPanel.setLayout(decorationPanelLayout);
        decorationPanelLayout.setHorizontalGroup(
            decorationPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(decorationPanelLayout.createSequentialGroup()
                .addContainerGap()
                .addGroup(decorationPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addGroup(decorationPanelLayout.createSequentialGroup()
                        .addGroup(decorationPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                            .addComponent(hexCharactersModeLabel)
                            .addComponent(positionCodeTypeLabel))
                        .addGap(132, 132, 132))
                    .addGroup(decorationPanelLayout.createSequentialGroup()
                        .addGroup(decorationPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                            .addComponent(backgroundModeLabel)
                            .addComponent(borderTypeLabel)
                            .addComponent(lineNumbersBackgroundCheckBox, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                            .addComponent(backgroundModeComboBox, 0, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                            .addComponent(linesPanel, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                            .addComponent(borderTypeComboBox, 0, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                            .addComponent(hexCharactersModeComboBox, 0, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                            .addComponent(positionCodeTypeComboBox, javax.swing.GroupLayout.Alignment.TRAILING, 0, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
                        .addContainerGap())))
        );
        decorationPanelLayout.setVerticalGroup(
            decorationPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(decorationPanelLayout.createSequentialGroup()
                .addContainerGap()
                .addComponent(backgroundModeLabel)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(backgroundModeComboBox, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(lineNumbersBackgroundCheckBox)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(linesPanel, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(borderTypeLabel)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(borderTypeComboBox, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(hexCharactersModeLabel)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(hexCharactersModeComboBox, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(positionCodeTypeLabel)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(positionCodeTypeComboBox, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addContainerGap(125, Short.MAX_VALUE))
        );

        verticalPanel.setBorder(javax.swing.BorderFactory.createTitledBorder("Vertical"));

        verticalScrollBarVisibilityModeLabel.setText("Vertical Scrollbar");

        verticalScrollBarVisibilityComboBox.setModel(new javax.swing.DefaultComboBoxModel<>(new String[] { "NEVER", "IF_NEEDED", "ALWAYS" }));
        verticalScrollBarVisibilityComboBox.setSelectedIndex(1);
        verticalScrollBarVisibilityComboBox.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                verticalScrollBarVisibilityComboBoxActionPerformed(evt);
            }
        });

        verticalScrollModeLabel.setText("Vertical Scroll Mode");

        verticalScrollModeComboBox.setModel(new javax.swing.DefaultComboBoxModel<>(new String[] { "PER_LINE", "PIXEL" }));
        verticalScrollModeComboBox.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                verticalScrollModeComboBoxActionPerformed(evt);
            }
        });

        verticalPositionLabel.setText("Vertical Scroll Position");

        verticalPositionTextField.setEditable(false);
        verticalPositionTextField.setText("0:0");

        javax.swing.GroupLayout verticalPanelLayout = new javax.swing.GroupLayout(verticalPanel);
        verticalPanel.setLayout(verticalPanelLayout);
        verticalPanelLayout.setHorizontalGroup(
            verticalPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(verticalPanelLayout.createSequentialGroup()
                .addContainerGap()
                .addGroup(verticalPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addComponent(verticalScrollBarVisibilityComboBox, 0, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                    .addComponent(verticalScrollModeComboBox, 0, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                    .addComponent(verticalPositionTextField)
                    .addGroup(verticalPanelLayout.createSequentialGroup()
                        .addGroup(verticalPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                            .addComponent(verticalScrollBarVisibilityModeLabel)
                            .addComponent(verticalScrollModeLabel)
                            .addComponent(verticalPositionLabel))
                        .addGap(0, 0, Short.MAX_VALUE)))
                .addContainerGap())
        );
        verticalPanelLayout.setVerticalGroup(
            verticalPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(verticalPanelLayout.createSequentialGroup()
                .addContainerGap()
                .addComponent(verticalScrollBarVisibilityModeLabel)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(verticalScrollBarVisibilityComboBox, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(verticalScrollModeLabel)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(verticalScrollModeComboBox, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(verticalPositionLabel)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(verticalPositionTextField, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addContainerGap(javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
        );

        horizontalPanel.setBorder(javax.swing.BorderFactory.createTitledBorder("Horizontal"));

        horizontalScrollBarVisibilityLabel.setText("Horizontal Scrollbar");

        horizontalScrollBarVisibilityComboBox.setModel(new javax.swing.DefaultComboBoxModel<>(new String[] { "NEVER", "IF_NEEDED", "ALWAYS" }));
        horizontalScrollBarVisibilityComboBox.setSelectedIndex(1);
        horizontalScrollBarVisibilityComboBox.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                horizontalScrollBarVisibilityComboBoxActionPerformed(evt);
            }
        });

        horizontalScrollModeLabel.setText("Horizontal Scroll Mode");

        horizontalScrollModeComboBox.setModel(new javax.swing.DefaultComboBoxModel<>(new String[] { "PER_CHAR", "PIXEL" }));
        horizontalScrollModeComboBox.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                horizontalScrollModeComboBoxActionPerformed(evt);
            }
        });

        horizontalPositionLabel.setText("Horizontal Scroll Position");

        horizontalPositionTextField.setEditable(false);
        horizontalPositionTextField.setText("0:0");

        javax.swing.GroupLayout horizontalPanelLayout = new javax.swing.GroupLayout(horizontalPanel);
        horizontalPanel.setLayout(horizontalPanelLayout);
        horizontalPanelLayout.setHorizontalGroup(
            horizontalPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(horizontalPanelLayout.createSequentialGroup()
                .addContainerGap()
                .addGroup(horizontalPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addComponent(horizontalScrollModeComboBox, 0, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                    .addComponent(horizontalScrollBarVisibilityComboBox, 0, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                    .addGroup(horizontalPanelLayout.createSequentialGroup()
                        .addGroup(horizontalPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                            .addComponent(horizontalScrollBarVisibilityLabel)
                            .addComponent(horizontalScrollModeLabel)
                            .addComponent(horizontalPositionLabel))
                        .addGap(0, 302, Short.MAX_VALUE))
                    .addComponent(horizontalPositionTextField))
                .addContainerGap())
        );
        horizontalPanelLayout.setVerticalGroup(
            horizontalPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(horizontalPanelLayout.createSequentialGroup()
                .addContainerGap()
                .addComponent(horizontalScrollBarVisibilityLabel)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(horizontalScrollBarVisibilityComboBox, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(horizontalScrollModeLabel)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(horizontalScrollModeComboBox, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(horizontalPositionLabel)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(horizontalPositionTextField, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addContainerGap(javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
        );

        horizontalByteShiftLabel.setText("Horizontal Byte Shift");

        horizontalByteShiftTextField.setEditable(false);
        horizontalByteShiftTextField.setText("0");

        javax.swing.GroupLayout scrollingPanelLayout = new javax.swing.GroupLayout(scrollingPanel);
        scrollingPanel.setLayout(scrollingPanelLayout);
        scrollingPanelLayout.setHorizontalGroup(
            scrollingPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(scrollingPanelLayout.createSequentialGroup()
                .addContainerGap()
                .addGroup(scrollingPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addComponent(verticalPanel, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                    .addComponent(horizontalPanel, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                    .addComponent(horizontalByteShiftTextField)
                    .addGroup(scrollingPanelLayout.createSequentialGroup()
                        .addComponent(horizontalByteShiftLabel)
                        .addGap(0, 0, Short.MAX_VALUE)))
                .addContainerGap())
        );
        scrollingPanelLayout.setVerticalGroup(
            scrollingPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(scrollingPanelLayout.createSequentialGroup()
                .addContainerGap()
                .addComponent(verticalPanel, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(horizontalPanel, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(horizontalByteShiftLabel)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(horizontalByteShiftTextField, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addContainerGap(88, Short.MAX_VALUE))
        );

        showShadowCursorCheckBox.setText("Show Shadow Cursor");
        showShadowCursorCheckBox.addItemListener(new java.awt.event.ItemListener() {
            public void itemStateChanged(java.awt.event.ItemEvent evt) {
                showShadowCursorCheckBoxItemStateChanged(evt);
            }
        });

        cursorRenderingModeLabel.setText("Cursor Rendering Mode");

        cursorRenderingModeComboBox.setModel(new javax.swing.DefaultComboBoxModel<>(new String[] { "PAINT", "XOR", "NEGATIVE" }));
        cursorRenderingModeComboBox.setSelectedIndex(1);
        cursorRenderingModeComboBox.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                cursorRenderingModeComboBoxActionPerformed(evt);
            }
        });

        cursorInsertShapeModeLabel.setText("Insert Cursor Shape");

        cursorInsertShapeComboBox.setModel(new javax.swing.DefaultComboBoxModel<>(new String[] { "LINE_BOTTOM", "LINE_TOP", "LINE_LEFT", "LINE_RIGHT", "DOUBLE_BOTTOM", "DOUBLE_TOP", "DOUBLE_LEFT", "DOUBLE_RIGHT", "QUARTER_BOTTOM", "QUARTER_TOP", "QUARTER_LEFT", "QUARTER_RIGHT", "HALF_BOTTOM", "HALF_TOP", "HALF_LEFT", "HALF_RIGHT", "BOX", "FRAME", "CORNERS", "BOTTOM_CORNERS" }));
        cursorInsertShapeComboBox.setSelectedIndex(6);
        cursorInsertShapeComboBox.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                cursorInsertShapeComboBoxActionPerformed(evt);
            }
        });

        cursorOverwriteShapeModeLabel.setText("Overwrite Cursor Shape");

        cursorOverwriteShapeComboBox.setModel(new javax.swing.DefaultComboBoxModel<>(new String[] { "LINE_BOTTOM", "LINE_TOP", "LINE_LEFT", "LINE_RIGHT", "DOUBLE_BOTTOM", "DOUBLE_TOP", "DOUBLE_LEFT", "DOUBLE_RIGHT", "QUARTER_BOTTOM", "QUARTER_TOP", "QUARTER_LEFT", "QUARTER_RIGHT", "HALF_BOTTOM", "HALF_TOP", "HALF_LEFT", "HALF_RIGHT", "BOX", "FRAME", "CORNERS", "BOTTOM_CORNERS" }));
        cursorOverwriteShapeComboBox.setSelectedIndex(16);
        cursorOverwriteShapeComboBox.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                cursorOverwriteShapeComboBoxActionPerformed(evt);
            }
        });

        cursorBlinkingRateLabel.setText("Cursor Blinking Rate");

        cursorBlinkingRateSpinner.addChangeListener(new javax.swing.event.ChangeListener() {
            public void stateChanged(javax.swing.event.ChangeEvent evt) {
                cursorBlinkingRateSpinnerStateChanged(evt);
            }
        });

        javax.swing.GroupLayout cursorPanelLayout = new javax.swing.GroupLayout(cursorPanel);
        cursorPanel.setLayout(cursorPanelLayout);
        cursorPanelLayout.setHorizontalGroup(
            cursorPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(cursorPanelLayout.createSequentialGroup()
                .addContainerGap()
                .addGroup(cursorPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addComponent(cursorRenderingModeComboBox, 0, 263, Short.MAX_VALUE)
                    .addComponent(cursorInsertShapeComboBox, 0, 263, Short.MAX_VALUE)
                    .addComponent(cursorOverwriteShapeComboBox, 0, 263, Short.MAX_VALUE)
                    .addGroup(cursorPanelLayout.createSequentialGroup()
                        .addGroup(cursorPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                            .addComponent(cursorRenderingModeLabel)
                            .addComponent(cursorInsertShapeModeLabel)
                            .addComponent(cursorOverwriteShapeModeLabel))
                        .addGap(0, 0, Short.MAX_VALUE))
                    .addComponent(showShadowCursorCheckBox, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                    .addGroup(cursorPanelLayout.createSequentialGroup()
                        .addComponent(cursorBlinkingRateLabel)
                        .addGap(63, 63, 63))
                    .addComponent(cursorBlinkingRateSpinner, javax.swing.GroupLayout.Alignment.TRAILING))
                .addContainerGap())
        );
        cursorPanelLayout.setVerticalGroup(
            cursorPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(javax.swing.GroupLayout.Alignment.TRAILING, cursorPanelLayout.createSequentialGroup()
                .addContainerGap()
                .addComponent(cursorBlinkingRateLabel)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(cursorBlinkingRateSpinner, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(cursorRenderingModeLabel)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(cursorRenderingModeComboBox, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(cursorInsertShapeModeLabel)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(cursorInsertShapeComboBox, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(cursorOverwriteShapeModeLabel)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(cursorOverwriteShapeComboBox, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(showShadowCursorCheckBox)
                .addContainerGap(266, Short.MAX_VALUE))
        );

        setLayout(new java.awt.BorderLayout());

        tabbedPane.addChangeListener(new javax.swing.event.ChangeListener() {
            public void stateChanged(javax.swing.event.ChangeEvent evt) {
                tabbedPaneStateChanged(evt);
            }
        });

        modeTab.setLayout(new java.awt.BorderLayout());
        tabbedPane.addTab("Mode", modeTab);

        stateTab.setLayout(new java.awt.BorderLayout());
        tabbedPane.addTab("State", stateTab);

        layoutTab.setLayout(new java.awt.BorderLayout());
        tabbedPane.addTab("Layout", layoutTab);

        decorationTab.setLayout(new java.awt.BorderLayout());
        tabbedPane.addTab("Decoration", decorationTab);

        scrollingTab.setLayout(new java.awt.BorderLayout());
        tabbedPane.addTab("Scrolling", scrollingTab);

        cursorTab.setLayout(new java.awt.BorderLayout());
        tabbedPane.addTab("Cursor", cursorTab);

        splitPane.setLeftComponent(tabbedPane);

        add(splitPane, java.awt.BorderLayout.CENTER);
    }// </editor-fold>//GEN-END:initComponents

    private void viewModeComboBoxActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_viewModeComboBoxActionPerformed
        codeArea.setViewMode(CodeAreaViewMode.values()[viewModeComboBox.getSelectedIndex()]);
    }//GEN-LAST:event_viewModeComboBoxActionPerformed

    private void lineLengthSpinnerStateChanged(javax.swing.event.ChangeEvent evt) {//GEN-FIRST:event_lineLengthSpinnerStateChanged
        // Not available in bined 0.2.2
    }//GEN-LAST:event_lineLengthSpinnerStateChanged

    private void charRenderingComboBoxActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_charRenderingComboBoxActionPerformed
        // Not available in bined 0.2.2
    }//GEN-LAST:event_charRenderingComboBoxActionPerformed

    private void backgroundModeComboBoxActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_backgroundModeComboBoxActionPerformed
        // Not available in bined 0.2.2
    }//GEN-LAST:event_backgroundModeComboBoxActionPerformed

    private void charAntialiasingComboBoxActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_charAntialiasingComboBoxActionPerformed
        // Not available in bined 0.2.2
    }//GEN-LAST:event_charAntialiasingComboBoxActionPerformed

    private void decoratorLineNumLineCheckBoxItemStateChanged(java.awt.event.ItemEvent evt) {//GEN-FIRST:event_decoratorLineNumLineCheckBoxItemStateChanged
        // Not available in bined 0.2.2
    }//GEN-LAST:event_decoratorLineNumLineCheckBoxItemStateChanged

    private void decoratorSplitLineCheckBoxItemStateChanged(java.awt.event.ItemEvent evt) {//GEN-FIRST:event_decoratorSplitLineCheckBoxItemStateChanged
        // Not available in bined 0.2.2
    }//GEN-LAST:event_decoratorSplitLineCheckBoxItemStateChanged

    private void decoratorBoxCheckBoxItemStateChanged(java.awt.event.ItemEvent evt) {//GEN-FIRST:event_decoratorBoxCheckBoxItemStateChanged
        // Not available in bined 0.2.2
    }//GEN-LAST:event_decoratorBoxCheckBoxItemStateChanged

    private void showHeaderCheckBoxItemStateChanged(java.awt.event.ItemEvent evt) {//GEN-FIRST:event_showHeaderCheckBoxItemStateChanged
        // Not available in bined 0.2.2
    }//GEN-LAST:event_showHeaderCheckBoxItemStateChanged

    private void showLineNumbersCheckBoxItemStateChanged(java.awt.event.ItemEvent evt) {//GEN-FIRST:event_showLineNumbersCheckBoxItemStateChanged
        // Not available in bined 0.2.2
    }//GEN-LAST:event_showLineNumbersCheckBoxItemStateChanged

    private void wrapLineModeCheckBoxItemStateChanged(java.awt.event.ItemEvent evt) {//GEN-FIRST:event_wrapLineModeCheckBoxItemStateChanged
        // Not available in bined 0.2.2
    }//GEN-LAST:event_wrapLineModeCheckBoxItemStateChanged

    private void lineNumbersBackgroundCheckBoxItemStateChanged(java.awt.event.ItemEvent evt) {//GEN-FIRST:event_lineNumbersBackgroundCheckBoxItemStateChanged
        // Not available in bined 0.2.2
    }//GEN-LAST:event_lineNumbersBackgroundCheckBoxItemStateChanged

    private void showShadowCursorCheckBoxItemStateChanged(java.awt.event.ItemEvent evt) {//GEN-FIRST:event_showShadowCursorCheckBoxItemStateChanged
        codeArea.setShowMirrorCursor(showShadowCursorCheckBox.isSelected());
    }//GEN-LAST:event_showShadowCursorCheckBoxItemStateChanged

    private void hexCharactersModeComboBoxActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_hexCharactersModeComboBoxActionPerformed
        codeArea.setCodeCharactersCase(CodeCharactersCase.values()[hexCharactersModeComboBox.getSelectedIndex()]);
    }//GEN-LAST:event_hexCharactersModeComboBoxActionPerformed

    private void codeTypeComboBoxActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_codeTypeComboBoxActionPerformed
        codeArea.setCodeType(CodeType.values()[codeTypeComboBox.getSelectedIndex()]);
    }//GEN-LAST:event_codeTypeComboBoxActionPerformed

    private void activeSectionComboBoxActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_activeSectionComboBoxActionPerformed
        // Not available in bined 0.2.2 - section is now an interface
    }//GEN-LAST:event_activeSectionComboBoxActionPerformed

    private void loadDataButtonActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_loadDataButtonActionPerformed
        JFileChooser openFC = new JFileChooser();
        openFC.removeChoosableFileFilter(openFC.getAcceptAllFileFilter());
        openFC.addChoosableFileFilter(new FileFilter() {
            @Override
            public boolean accept(File file) {
                return file.isFile();
            }

            @Override
            public String getDescription() {
                return "All Files (*)";
            }
        });
        if (openFC.showOpenDialog(getParentFrame()) == JFileChooser.APPROVE_OPTION) {
            try {
                File selectedFile = openFC.getSelectedFile();
                try (FileInputStream stream = new FileInputStream(selectedFile)) {
                    ((EditableBinaryData) codeArea.getContentData()).loadFromStream(stream);
                    codeArea.notifyDataChanged();
                    codeArea.setActiveCaretPosition(0);
                }
            } catch (IOException ex) {
                Logger.getLogger(DeltaHexPanel.class.getName()).log(Level.SEVERE, null, ex);
            }
        }
    }//GEN-LAST:event_loadDataButtonActionPerformed

    private void saveDataButtonActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_saveDataButtonActionPerformed
        JFileChooser saveFC = new JFileChooser();
        saveFC.removeChoosableFileFilter(saveFC.getAcceptAllFileFilter());
        saveFC.addChoosableFileFilter(new FileFilter() {
            @Override
            public boolean accept(File file) {
                return file.isFile();
            }

            @Override
            public String getDescription() {
                return "All Files (*)";
            }
        });
        if (saveFC.showSaveDialog(getParentFrame()) == JFileChooser.APPROVE_OPTION) {
            try {
                File selectedFile = saveFC.getSelectedFile();
                try (FileOutputStream stream = new FileOutputStream(selectedFile)) {
                    codeArea.getContentData().saveToStream(stream);
                }
            } catch (IOException ex) {
                Logger.getLogger(DeltaHexPanel.class.getName()).log(Level.SEVERE, null, ex);
            }
        }
    }//GEN-LAST:event_saveDataButtonActionPerformed

    private void borderTypeComboBoxActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_borderTypeComboBoxActionPerformed
        codeArea.setBorder(getBorderByType(borderTypeComboBox.getSelectedIndex()));
    }//GEN-LAST:event_borderTypeComboBoxActionPerformed

    private void decoratorHeaderLineCheckBoxItemStateChanged(java.awt.event.ItemEvent evt) {//GEN-FIRST:event_decoratorHeaderLineCheckBoxItemStateChanged
        // Not available in bined 0.2.2
    }//GEN-LAST:event_decoratorHeaderLineCheckBoxItemStateChanged

    private void headerSpaceComboBoxActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_headerSpaceComboBoxActionPerformed
        // Not available in bined 0.2.2
    }//GEN-LAST:event_headerSpaceComboBoxActionPerformed

    private void lineNumbersSpaceComboBoxActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_lineNumbersSpaceComboBoxActionPerformed
        // Not available in bined 0.2.2
    }//GEN-LAST:event_lineNumbersSpaceComboBoxActionPerformed

    private void lineNumbersLengthComboBoxActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_lineNumbersLengthComboBoxActionPerformed
        // Not available in bined 0.2.2
    }//GEN-LAST:event_lineNumbersLengthComboBoxActionPerformed

    private void positionCodeTypeComboBoxActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_positionCodeTypeComboBoxActionPerformed
        // Not available in bined 0.2.2
    }//GEN-LAST:event_positionCodeTypeComboBoxActionPerformed

    private void headerSpaceSpinnerStateChanged(javax.swing.event.ChangeEvent evt) {//GEN-FIRST:event_headerSpaceSpinnerStateChanged
        // Not available in bined 0.2.2
    }//GEN-LAST:event_headerSpaceSpinnerStateChanged

    private void lineNumbersSpaceSpinnerStateChanged(javax.swing.event.ChangeEvent evt) {//GEN-FIRST:event_lineNumbersSpaceSpinnerStateChanged
        // Not available in bined 0.2.2
    }//GEN-LAST:event_lineNumbersSpaceSpinnerStateChanged

    private void lineNumbersLengthSpinnerStateChanged(javax.swing.event.ChangeEvent evt) {//GEN-FIRST:event_lineNumbersLengthSpinnerStateChanged
        // Not available in bined 0.2.2
    }//GEN-LAST:event_lineNumbersLengthSpinnerStateChanged

    private void fontFamilyComboBoxActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_fontFamilyComboBoxActionPerformed
        int size = codeArea.getFont().getSize();
        switch (fontFamilyComboBox.getSelectedIndex()) {
            case 0: {
                codeArea.setFont(new Font(Font.DIALOG, Font.PLAIN, size));
                break;
            }
            case 1: {
                codeArea.setFont(new Font(Font.MONOSPACED, Font.PLAIN, size));
                break;
            }
            case 2: {
                codeArea.setFont(new Font(Font.SERIF, Font.PLAIN, size));
                break;
            }
        }
    }//GEN-LAST:event_fontFamilyComboBoxActionPerformed

    private void charsetComboBoxActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_charsetComboBoxActionPerformed
        codeArea.setCharset(Charset.forName((String) charsetComboBox.getSelectedItem()));
    }//GEN-LAST:event_charsetComboBoxActionPerformed

    private void editationAllowedComboBoxActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_editationAllowedComboBoxActionPerformed
        // Not available in bined 0.2.2
    }//GEN-LAST:event_editationAllowedComboBoxActionPerformed

    private void tabbedPaneStateChanged(javax.swing.event.ChangeEvent evt) {//GEN-FIRST:event_tabbedPaneStateChanged
        Component tab = tabbedPane.getSelectedComponent();
        if (tab != null && tab != activeTab && !tabMap.isEmpty()) {
            if (activeTab != null) {
                ((JPanel) activeTab).remove(tabMap.get(activeTab));
            }

            ((JPanel) tab).add(tabMap.get((JPanel) tab), BorderLayout.CENTER);
            activeTab = (JPanel) tab;
        }
    }//GEN-LAST:event_tabbedPaneStateChanged

    private void verticalScrollModeComboBoxActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_verticalScrollModeComboBoxActionPerformed
        // Not available in bined 0.2.2
    }//GEN-LAST:event_verticalScrollModeComboBoxActionPerformed

    private void verticalScrollBarVisibilityComboBoxActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_verticalScrollBarVisibilityComboBoxActionPerformed
        codeArea.setVerticalScrollBarVisibility(ScrollBarVisibility.values()[verticalScrollBarVisibilityComboBox.getSelectedIndex()]);
    }//GEN-LAST:event_verticalScrollBarVisibilityComboBoxActionPerformed

    private void horizontalScrollModeComboBoxActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_horizontalScrollModeComboBoxActionPerformed
        // Not available in bined 0.2.2
    }//GEN-LAST:event_horizontalScrollModeComboBoxActionPerformed

    private void horizontalScrollBarVisibilityComboBoxActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_horizontalScrollBarVisibilityComboBoxActionPerformed
        codeArea.setHorizontalScrollBarVisibility(ScrollBarVisibility.values()[horizontalScrollBarVisibilityComboBox.getSelectedIndex()]);
    }//GEN-LAST:event_horizontalScrollBarVisibilityComboBoxActionPerformed

    private void cursorRenderingModeComboBoxActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_cursorRenderingModeComboBoxActionPerformed
        // Not available in bined 0.2.2
    }//GEN-LAST:event_cursorRenderingModeComboBoxActionPerformed

    private void cursorInsertShapeComboBoxActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_cursorInsertShapeComboBoxActionPerformed
        // Not available in bined 0.2.2
    }//GEN-LAST:event_cursorInsertShapeComboBoxActionPerformed

    private void cursorOverwriteShapeComboBoxActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_cursorOverwriteShapeComboBoxActionPerformed
        // Not available in bined 0.2.2
    }//GEN-LAST:event_cursorOverwriteShapeComboBoxActionPerformed

    private void cursorBlinkingRateSpinnerStateChanged(javax.swing.event.ChangeEvent evt) {//GEN-FIRST:event_cursorBlinkingRateSpinnerStateChanged
        // Not available in bined 0.2.2
    }//GEN-LAST:event_cursorBlinkingRateSpinnerStateChanged

    private void byteGroupSizeSpinnerStateChanged(javax.swing.event.ChangeEvent evt) {//GEN-FIRST:event_byteGroupSizeSpinnerStateChanged
        // Not available in bined 0.2.2
    }//GEN-LAST:event_byteGroupSizeSpinnerStateChanged

    private void spaceGroupSizeSpinnerStateChanged(javax.swing.event.ChangeEvent evt) {//GEN-FIRST:event_spaceGroupSizeSpinnerStateChanged
        // Not available in bined 0.2.2
    }//GEN-LAST:event_spaceGroupSizeSpinnerStateChanged

    private void fontSizeComboBoxActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_fontSizeComboBoxActionPerformed
        Font font = codeArea.getFont();
        Font derivedFont = font.deriveFont(Font.PLAIN, Integer.valueOf((String) fontSizeComboBox.getSelectedItem()));
        codeArea.setFont(derivedFont);
    }//GEN-LAST:event_fontSizeComboBoxActionPerformed

    private void showNonprintableCharactersCheckBoxItemStateChanged(java.awt.event.ItemEvent evt) {//GEN-FIRST:event_showNonprintableCharactersCheckBoxItemStateChanged
        // Not available in bined 0.2.2
    }//GEN-LAST:event_showNonprintableCharactersCheckBoxItemStateChanged

    // Variables declaration - do not modify//GEN-BEGIN:variables
    private javax.swing.JComboBox<String> activeSectionComboBox;
    private javax.swing.JLabel activeSectionLabel;
    private javax.swing.JComboBox<String> backgroundModeComboBox;
    private javax.swing.JLabel backgroundModeLabel;
    private javax.swing.JComboBox<String> borderTypeComboBox;
    private javax.swing.JLabel borderTypeLabel;
    private javax.swing.JLabel byteGroupSizeLabel;
    private javax.swing.JSpinner byteGroupSizeSpinner;
    private javax.swing.JComboBox<String> charAntialiasingComboBox;
    private javax.swing.JLabel charAntialiasingScrollModeLabel;
    private javax.swing.JComboBox<String> charRenderingComboBox;
    private javax.swing.JLabel charRenderingScrollModeLabel;
    private javax.swing.JComboBox<String> charsetComboBox;
    private javax.swing.JLabel charsetLabel;
    private javax.swing.JLabel codeOffsetLabel;
    private javax.swing.JTextField codeOffsetTextField;
    private javax.swing.JComboBox<String> codeTypeComboBox;
    private javax.swing.JLabel codeTypeScrollModeLabel;
    private javax.swing.JLabel cursorBlinkingRateLabel;
    private javax.swing.JSpinner cursorBlinkingRateSpinner;
    private javax.swing.JComboBox<String> cursorInsertShapeComboBox;
    private javax.swing.JLabel cursorInsertShapeModeLabel;
    private javax.swing.JComboBox<String> cursorOverwriteShapeComboBox;
    private javax.swing.JLabel cursorOverwriteShapeModeLabel;
    private javax.swing.JPanel cursorPanel;
    private javax.swing.JComboBox<String> cursorRenderingModeComboBox;
    private javax.swing.JLabel cursorRenderingModeLabel;
    private javax.swing.JPanel cursorTab;
    private javax.swing.JLabel dataSizeLabel;
    private javax.swing.JTextField dataSizeTextField;
    private javax.swing.JPanel decorationPanel;
    private javax.swing.JPanel decorationTab;
    private javax.swing.JCheckBox decoratorBoxCheckBox;
    private javax.swing.JCheckBox decoratorHeaderLineCheckBox;
    private javax.swing.JCheckBox decoratorLineNumLineCheckBox;
    private javax.swing.JCheckBox decoratorSplitLineCheckBox;
    private javax.swing.JComboBox<String> editationAllowedComboBox;
    private javax.swing.JLabel editationAllowedLabel;
    private javax.swing.JComboBox<String> fontFamilyComboBox;
    private javax.swing.JLabel fontFamilyLabel;
    private javax.swing.JPanel fontPanel;
    private javax.swing.JComboBox<String> fontSizeComboBox;
    private javax.swing.JLabel fontSizeLabel;
    private javax.swing.JPanel headerPanel;
    private javax.swing.JComboBox<String> headerSpaceComboBox;
    private javax.swing.JLabel headerSpaceLabel;
    private javax.swing.JSpinner headerSpaceSpinner;
    private javax.swing.JComboBox<String> hexCharactersModeComboBox;
    private javax.swing.JLabel hexCharactersModeLabel;
    private javax.swing.JLabel horizontalByteShiftLabel;
    private javax.swing.JTextField horizontalByteShiftTextField;
    private javax.swing.JPanel horizontalPanel;
    private javax.swing.JLabel horizontalPositionLabel;
    private javax.swing.JTextField horizontalPositionTextField;
    private javax.swing.JComboBox<String> horizontalScrollBarVisibilityComboBox;
    private javax.swing.JLabel horizontalScrollBarVisibilityLabel;
    private javax.swing.JComboBox<String> horizontalScrollModeComboBox;
    private javax.swing.JLabel horizontalScrollModeLabel;
    private javax.swing.JPanel layoutPanel;
    private javax.swing.JPanel layoutTab;
    private javax.swing.JLabel lineLengthLabel;
    private javax.swing.JSpinner lineLengthSpinner;
    private javax.swing.JCheckBox lineNumbersBackgroundCheckBox;
    private javax.swing.JComboBox<String> lineNumbersLengthComboBox;
    private javax.swing.JLabel lineNumbersLengthLabel;
    private javax.swing.JSpinner lineNumbersLengthSpinner;
    private javax.swing.JPanel lineNumbersPanel;
    private javax.swing.JComboBox<String> lineNumbersSpaceComboBox;
    private javax.swing.JLabel lineNumbersSpaceLabel;
    private javax.swing.JSpinner lineNumbersSpaceSpinner;
    private javax.swing.JPanel linesPanel;
    private javax.swing.JButton loadDataButton;
    private javax.swing.JPanel modePanel;
    private javax.swing.JPanel modeTab;
    private javax.swing.JComboBox<String> positionCodeTypeComboBox;
    private javax.swing.JLabel positionCodeTypeLabel;
    private javax.swing.JLabel positionLabel;
    private javax.swing.JPanel positionPanel;
    private javax.swing.JTextField positionTextField;
    private javax.swing.JButton saveDataButton;
    private javax.swing.JPanel scrollingPanel;
    private javax.swing.JPanel scrollingTab;
    private javax.swing.JLabel selectionEndLabel;
    private javax.swing.JTextField selectionEndTextField;
    private javax.swing.JPanel selectionPanel;
    private javax.swing.JLabel selectionStartLabel;
    private javax.swing.JTextField selectionStartTextField;
    private javax.swing.JCheckBox showHeaderCheckBox;
    private javax.swing.JCheckBox showLineNumbersCheckBox;
    private javax.swing.JCheckBox showNonprintableCharactersCheckBox;
    private javax.swing.JCheckBox showShadowCursorCheckBox;
    private javax.swing.JLabel spaceGroupSizeLabel;
    private javax.swing.JSpinner spaceGroupSizeSpinner;
    private javax.swing.JSplitPane splitPane;
    private javax.swing.JPanel statePanel;
    private javax.swing.JPanel stateTab;
    private javax.swing.JTabbedPane tabbedPane;
    private javax.swing.JPanel verticalPanel;
    private javax.swing.JLabel verticalPositionLabel;
    private javax.swing.JTextField verticalPositionTextField;
    private javax.swing.JComboBox<String> verticalScrollBarVisibilityComboBox;
    private javax.swing.JLabel verticalScrollBarVisibilityModeLabel;
    private javax.swing.JComboBox<String> verticalScrollModeComboBox;
    private javax.swing.JLabel verticalScrollModeLabel;
    private javax.swing.JComboBox<String> viewModeComboBox;
    private javax.swing.JLabel viewModeScrollModeLabel;
    private javax.swing.JCheckBox wrapLineModeCheckBox;
    // End of variables declaration//GEN-END:variables

    private Border getBorderByType(int borderTypeIndex) {
        switch (borderTypeIndex) {
            case 0: {
                return null;
            }
            case 1: {
                return new EmptyBorder(5, 5, 5, 5);
            }
            case 2: {
                return new BasicBorders.MarginBorder();
            }
            case 3: {
                return new BevelBorder(BevelBorder.RAISED);
            }
            case 4: {
                return new BevelBorder(BevelBorder.LOWERED);
            }
            case 5: {
                return new EtchedBorder(EtchedBorder.RAISED);
            }
            case 6: {
                return new EtchedBorder(EtchedBorder.LOWERED);
            }
            case 7: {
                return new LineBorder(Color.BLACK);
            }
        }

        return null;
    }
}
