// R-20: Scanner.registerAuditIssueHandler through the public Montoya API.
// A purpose-built test extension, not evidence of unmodified BApp parity.
import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;

public class IssueHandlerExtension implements BurpExtension {
    @Override
    public void initialize(MontoyaApi api) {
        api.extension().setName("Audit issue handler regression");
        api.scanner().registerAuditIssueHandler(issue ->
            api.logging().logToError("audit issue handler saw: " + issue.name() + " @ " + issue.baseUrl()));
        api.logging().logToError("audit issue handler registered");
    }
}
