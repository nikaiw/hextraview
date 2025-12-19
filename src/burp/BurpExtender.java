package burp;

import java.io.PrintWriter;

public class BurpExtender implements IBurpExtender {

    public static final String VERSION = "1.0.0";

    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
        callbacks.setExtensionName("HextraView");

        // Print build info to Burp output
        PrintWriter stdout = new PrintWriter(callbacks.getStdout(), true);
        stdout.println("===========================================");
        stdout.println("  HextraView - Enhanced Hex Editor");
        stdout.println("  Version: " + VERSION);
        stdout.println("  Build:   " + BuildInfo.BUILD_TIMESTAMP);
        stdout.println("  Commit:  " + BuildInfo.GIT_COMMIT);
        stdout.println("===========================================");

        callbacks.registerMessageEditorTabFactory((controller, editable) -> new ViewStateTab(callbacks, controller, editable));

        stdout.println("HextraView loaded successfully!");
    }
}
