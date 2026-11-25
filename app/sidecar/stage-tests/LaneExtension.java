// AR-08 test extension: an active scan check whose request WebProbe can
// hold, and an HTTP handler that marks every request. While the check's
// request is in flight, the HTTP handler must still answer: a scan check
// must not block proxied traffic. Compiled by the ext_host tests.

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.Http;
import burp.api.montoya.http.handler.HttpHandler;
import burp.api.montoya.http.handler.HttpRequestToBeSent;
import burp.api.montoya.http.handler.HttpResponseReceived;
import burp.api.montoya.http.handler.RequestToBeSentAction;
import burp.api.montoya.http.handler.ResponseReceivedAction;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.scanner.AuditResult;
import burp.api.montoya.scanner.ConsolidationAction;
import burp.api.montoya.scanner.audit.insertionpoint.AuditInsertionPoint;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import burp.api.montoya.scanner.audit.issues.AuditIssueConfidence;
import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity;
import burp.api.montoya.scanner.scancheck.ActiveScanCheck;
import burp.api.montoya.scanner.scancheck.ScanCheckType;

import java.util.List;

public class LaneExtension implements BurpExtension, HttpHandler {
    @Override
    public void initialize(MontoyaApi api) {
        api.extension().setName("Lanes");
        api.http().registerHttpHandler(this);
        api.scanner().registerActiveScanCheck(new ActiveScanCheck() {
            public String checkName() { return "lane check"; }
            public AuditResult doCheck(HttpRequestResponse base, AuditInsertionPoint point, Http http) {
                HttpRequest probe = point.buildHttpRequestWithPayload(ByteArray.byteArray("lane"));
                HttpRequestResponse rr = http.sendRequest(probe);
                if (!rr.hasResponse()) return AuditResult.auditResult(List.of());
                return AuditResult.auditResult(AuditIssue.auditIssue("Lane check", "The held request came back.", "",
                        base.request().url(), AuditIssueSeverity.INFORMATION, AuditIssueConfidence.CERTAIN, null, null,
                        AuditIssueSeverity.INFORMATION, rr));
            }
            public ConsolidationAction consolidateIssues(AuditIssue a, AuditIssue b) { return ConsolidationAction.KEEP_EXISTING; }
        }, ScanCheckType.PER_INSERTION_POINT);
    }

    @Override
    public RequestToBeSentAction handleHttpRequestToBeSent(HttpRequestToBeSent req) {
        return RequestToBeSentAction.continueWith(req.withAddedHeader("X-Lane", "hook"));
    }

    @Override
    public ResponseReceivedAction handleHttpResponseReceived(HttpResponseReceived resp) {
        return ResponseReceivedAction.continueWith(resp);
    }
}
