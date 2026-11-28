// R-20: registerHotKeyHandler is accepted and api.project() answers.
// A purpose-built test extension, not evidence of unmodified BApp parity.
import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.ui.hotkey.HotKey;
import burp.api.montoya.ui.hotkey.HotKeyContext;

public class HotKeyProjectExtension implements BurpExtension {
    private static void check(boolean ok, String message) {
        if (!ok) throw new AssertionError(message);
    }

    @Override
    public void initialize(MontoyaApi api) {
        api.extension().setName("Hotkey and project regression");
        HotKey key = HotKey.hotKey("Do thing", "Ctrl+Shift+Y");
        check("Do thing".equals(key.name()) && "Ctrl+Shift+Y".equals(key.hotkey()), "HotKey keeps its name and keys");
        var a = api.userInterface().registerHotKeyHandler(key, event -> { });
        var b = api.userInterface().registerHotKeyHandler(HotKeyContext.HTTP_MESSAGE_EDITOR, "Ctrl+Shift+U", event -> { });
        var c = api.userInterface().registerHotKeyHandler(HotKeyContext.HTTP_MESSAGE_EDITOR, key, event -> { });
        check(a.isRegistered() && b.isRegistered() && c.isRegistered(), "registrations are live");
        a.deregister();
        check(!a.isRegistered(), "deregister works");
        check(!api.project().name().isEmpty(), "project has a name");
        check(api.project().id().equals(api.project().id()), "project id is stable within a session");
        api.logging().logToError("hotkey and project regression passed");
    }
}
