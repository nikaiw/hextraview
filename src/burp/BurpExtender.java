package burp;

import java.io.PrintWriter;

public class BurpExtender implements IBurpExtender, IExtensionStateListener {

    private PrintWriter stdout;

    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
        callbacks.setExtensionName("HextraView");

        // Print build info to Burp output
        stdout = new PrintWriter(callbacks.getStdout(), true);
        stdout.println("===========================================");
        stdout.println("  HextraView - Enhanced Hex Editor");
        stdout.println("  Version: " + BuildInfo.VERSION);
        stdout.println("  Build:   " + BuildInfo.BUILD_TIMESTAMP);
        stdout.println("  Commit:  " + BuildInfo.GIT_COMMIT);
        stdout.println("===========================================");

        // Register the extension state listener for proper cleanup
        callbacks.registerExtensionStateListener(this);

        callbacks.registerMessageEditorTabFactory((controller, editable) -> new ViewStateTab(callbacks, controller, editable));

        stdout.println("HextraView loaded successfully!");
    }

    @Override
    public void extensionUnloaded() {
        if (stdout != null) {
            stdout.println("HextraView unloaded.");
        }
        // Additional cleanup can be added here if needed
    }
}
