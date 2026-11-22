import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.http.handler.*;
import burp.api.montoya.http.message.responses.analysis.ResponseKeywordsAnalyzer;
import java.nio.file.*;
import java.util.*;
public class ParityProbe implements BurpExtension {
    private MontoyaApi api;
    private final List<String> lines = new ArrayList<>();
    private void log(String key, Object value) {
        String line = key + "=" + String.valueOf(value);
        lines.add(line); api.logging().logToOutput(line);
    }
    private void snapshot(String name, ResponseKeywordsAnalyzer a) {
        log(name + ".variant", new TreeSet<>(a.variantKeywords()));
        log(name + ".invariant", new TreeSet<>(a.invariantKeywords()));
    }
    @Override public void initialize(MontoyaApi api) {
        this.api = api;
        api.extension().setName("Local parity probe");
        try {
            log("product", api.burpSuite().version().name());
            var a = api.http().createResponseKeywordsAnalyzer(List.of("token", "TOKEN", "absent", "X-Flag"));
            snapshot("before", a);
            a.updateWith(HttpResponse.httpResponse("HTTP/1.1 200 OK\r\nX-Flag: yes\r\n\r\ntoken token TOKEN"));
            snapshot("first", a);
            a.updateWith(HttpResponse.httpResponse("HTTP/1.1 200 OK\r\nX-Flag: yes\r\n\r\ntoken TOKEN"));
            snapshot("second", a);
            a.updateWith(HttpResponse.httpResponse("HTTP/1.1 200 OK\r\n\r\ntoken token TOKEN"));
            snapshot("third", a);
            var overlap = api.http().createResponseKeywordsAnalyzer(List.of("aa"));
            overlap.updateWith(HttpResponse.httpResponse("HTTP/1.1 200 OK\r\n\r\naaaa"));
            overlap.updateWith(HttpResponse.httpResponse("HTTP/1.1 200 OK\r\n\r\naaaaa"));
            snapshot("overlap", overlap);
            try { api.http().createResponseKeywordsAnalyzer(List.of("")); log("emptyKeyword", "accepted"); }
            catch (Throwable t) { log("emptyKeyword", t.getClass().getSimpleName()); }
            try { var v = api.http().createResponseVariationsAnalyzer(); log("variations", v.getClass().getName()); }
            catch (Throwable t) { log("variations", t.getClass().getSimpleName()); }
            api.http().registerHttpHandler(new HttpHandler() {
                public RequestToBeSentAction handleHttpRequestToBeSent(HttpRequestToBeSent request) {
                    return RequestToBeSentAction.continueWith(request.withAddedHeader("X-Parity-Probe", "1"));
                }
                public ResponseReceivedAction handleHttpResponseReceived(HttpResponseReceived response) {
                    return ResponseReceivedAction.continueWith(response);
                }
            });
            var request = HttpRequest.httpRequestFromUrl("http://127.0.0.1:18765/echo?value=probe");
            var pair = api.http().sendRequest(request);
            log("sendRequest.status", pair.hasResponse() ? pair.response().statusCode() : "no-response");
            log("sendRequest.body", pair.hasResponse() ? pair.response().bodyToString() : "");
            api.repeater().sendToRepeater(request, "Parity loopback");
            int start = request.toString().indexOf("probe");
            api.intruder().sendToIntruder(request.httpService(), burp.api.montoya.intruder.HttpRequestTemplate.httpRequestTemplate(request.toByteArray(), List.of(burp.api.montoya.core.Range.range(start, start + 5))));
            api.decoder().sendToDecoder(ByteArray.byteArray("SGVsbG8="));
            api.comparer().sendToComparer(ByteArray.byteArray("alpha"), ByteArray.byteArray("alpHa"));
            log("toolsPopulated", true);
        } catch (Throwable t) { log("fatal", t.getClass().getName() + ":" + t.getMessage()); }
        try {
            String label = api.burpSuite().version().name().replaceAll("[^A-Za-z0-9]", "");
            Files.write(Path.of("/downloads/burp-comparison/probe-" + label + ".txt"), lines);
        } catch (Exception e) { api.logging().logToError(e.toString()); }
    }
}
