package burp;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;

/**
 * Montoya API entry point for HextraView.
 * Registers hex editor tabs for HTTP requests, HTTP responses,
 * and WebSocket messages.
 *
 * When both a legacy {@code IBurpExtender} and a Montoya {@code BurpExtension}
 * are present in the same JAR, Burp Suite only loads the Montoya entry point.
 * All registration is therefore done here.
 */
public class HextraViewMontoya implements BurpExtension {

    @Override
    public void initialize(MontoyaApi api) {
        api.extension().setName("HextraView");

        api.logging().logToOutput("===========================================");
        api.logging().logToOutput("  HextraView - Enhanced Hex Editor");
        api.logging().logToOutput("  Version: " + BuildInfo.VERSION);
        api.logging().logToOutput("  Build:   " + BuildInfo.BUILD_TIMESTAMP);
        api.logging().logToOutput("  Commit:  " + BuildInfo.GIT_COMMIT);
        api.logging().logToOutput("===========================================");

        // HTTP editors (request + response)
        api.userInterface().registerHttpRequestEditorProvider(
                context -> new HttpHexTab(api, true));
        api.userInterface().registerHttpResponseEditorProvider(
                context -> new HttpHexTab(api, false));

        // WebSocket editor
        api.userInterface().registerWebSocketMessageEditorProvider(
                context -> new WebSocketHexTab(api));

        api.logging().logToOutput("HextraView loaded successfully!");
    }
}
