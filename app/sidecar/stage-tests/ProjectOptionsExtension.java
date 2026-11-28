// R-20: burpSuite().exportProjectOptionsAsJson through the public Montoya API.
// A purpose-built test extension, not evidence of unmodified BApp parity.
import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;

public class ProjectOptionsExtension implements BurpExtension {
    private static void check(boolean ok, String message) {
        if (!ok) throw new AssertionError(message);
    }

    @Override
    public void initialize(MontoyaApi api) {
        api.extension().setName("Project options regression");
        String all = api.burpSuite().exportProjectOptionsAsJson();
        check(all.contains("\"request_listeners\"") && all.contains("\"enable_http2\""), "everything: " + all);
        String part = api.burpSuite().exportProjectOptionsAsJson("http.http2");
        check(part.contains("\"enable_http2\"") && !part.contains("request_listeners"), "one path: " + part);
        String two = api.burpSuite().exportProjectOptionsAsJson("proxy.request_listeners", "no.such.path");
        check(two.contains("\"listener_port\"") && !two.contains("enable_http2"), "two paths: " + two);
        api.logging().logToError("project options regression passed");
    }
}
