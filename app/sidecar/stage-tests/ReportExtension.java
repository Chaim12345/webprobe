// R-20: Scanner.generateReport through the public Montoya API.
// A purpose-built test extension, not evidence of unmodified BApp parity.
import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.scanner.ReportFormat;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import burp.api.montoya.scanner.audit.issues.AuditIssueConfidence;
import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

public class ReportExtension implements BurpExtension {
    private static void check(boolean ok, String message) {
        if (!ok) throw new AssertionError(message);
    }

    @Override
    public void initialize(MontoyaApi api) {
        api.extension().setName("Report regression");
        try {
            var issues = List.of(
                AuditIssue.auditIssue("First <issue>", "Detail with ]]> inside", "Fix it", "https://a.test:8443/admin?x=1",
                    AuditIssueSeverity.HIGH, AuditIssueConfidence.CERTAIN, null, null, AuditIssueSeverity.HIGH),
                AuditIssue.auditIssue("Second", null, null, "http://b.test",
                    AuditIssueSeverity.INFORMATION, AuditIssueConfidence.TENTATIVE, null, null, AuditIssueSeverity.INFORMATION));
            Path xml = Files.createTempFile("wp-report", ".xml");
            Path html = Files.createTempFile("wp-report", ".html");
            api.scanner().generateReport(issues, ReportFormat.XML, xml);
            api.scanner().generateReport(issues, ReportFormat.HTML, html);
            String x = Files.readString(xml);
            var doc = javax.xml.parsers.DocumentBuilderFactory.newInstance().newDocumentBuilder().parse(xml.toFile());
            var nodes = doc.getElementsByTagName("issue");
            check(nodes.getLength() == 2, "two issues in the XML");
            check(doc.getElementsByTagName("name").item(0).getTextContent().equals("First <issue>"), "name survives CDATA");
            check(doc.getElementsByTagName("issueDetail").item(0).getTextContent().equals("Detail with ]]> inside"), "a CDATA end marker in the detail survives");
            check(doc.getElementsByTagName("host").item(0).getTextContent().equals("https://a.test:8443"), "host is the origin: " + x);
            check(doc.getElementsByTagName("path").item(0).getTextContent().equals("/admin?x=1"), "path");
            check(doc.getElementsByTagName("path").item(1).getTextContent().equals("/"), "a base URL with no path reads as /");
            check(doc.getElementsByTagName("severity").item(0).getTextContent().equals("High"), "severity label");
            check(doc.getElementsByTagName("severity").item(1).getTextContent().equals("Information"), "information label");
            check(doc.getElementsByTagName("confidence").item(1).getTextContent().equals("Tentative"), "confidence label");
            check(doc.getElementsByTagName("issueDetail").getLength() == 1, "an issue with no detail has no detail element");
            String h = Files.readString(html);
            check(h.contains("1. First &lt;issue&gt;") && h.contains("2. Second") && h.contains("Fix it"), "HTML lists both issues: " + h);
            Files.deleteIfExists(xml);
            Files.deleteIfExists(html);
            api.logging().logToError("report regression passed");
        } catch (Exception e) {
            throw new AssertionError(e);
        }
    }
}
