// R-20: Scanner.startAudit through the public Montoya API. The request to
// audit is the one Proxy history item the test provides. A purpose-built
// test extension, not evidence of unmodified BApp parity.
import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.scanner.AuditConfiguration;
import burp.api.montoya.scanner.BuiltInAuditConfiguration;
import burp.api.montoya.scanner.audit.Audit;

public class StartAuditExtension implements BurpExtension {
    @Override
    public void initialize(MontoyaApi api) {
        api.extension().setName("startAudit regression");
        Audit audit = api.scanner().startAudit(AuditConfiguration.auditConfiguration(BuiltInAuditConfiguration.LEGACY_ACTIVE_AUDIT_CHECKS));
        api.logging().logToError("audit before: " + audit.statusMessage() + " requests=" + audit.requestCount());
        // A request alone: WebProbe fetches the response to audit against.
        audit.addRequest(api.proxy().history().get(0).finalRequest());
        Thread watch = new Thread(() -> {
            try {
                for (int i = 0; i < 300 && !"Audit finished".equals(audit.statusMessage()); i++) Thread.sleep(100);
                api.logging().logToError("audit status: " + audit.statusMessage() + " requests=" + audit.requestCount() + " issues=" + audit.issues().size());
                audit.delete();
                api.logging().logToError("audit after delete: " + audit.statusMessage());
            } catch (Throwable t) {
                api.logging().logToError("audit watch failed: " + t);
            }
        }, "audit-watch");
        watch.setDaemon(true);
        watch.start();
    }
}
