// R-20: exercise response keyword analysis through the public Montoya API.
// This is a purpose-built test extension, not evidence of unmodified BApp parity.
import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.responses.HttpResponse;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;

public class KeywordAnalysisExtension implements BurpExtension {
    private static void check(boolean ok, String message) {
        if (!ok) throw new AssertionError(message);
    }

    @Override
    public void initialize(MontoyaApi api) {
        api.extension().setName("Keyword analysis regression");
        var keywords = new ArrayList<>(List.of("token", "absent", "TOKEN", "X-Flag", "token"));
        var analyzer = api.http().createResponseKeywordsAnalyzer(keywords);
        keywords.clear(); // The analyzer owns a snapshot, not the caller's mutable list.
        check(analyzer.variantKeywords().isEmpty(), "no variants before any response");
        check(analyzer.invariantKeywords().isEmpty(), "no invariants before any response");
        analyzer.updateWith(HttpResponse.httpResponse("HTTP/1.1 200 OK\r\nX-Flag: yes\r\n\r\ntoken token TOKEN"));
        check(analyzer.invariantKeywords().equals(Set.of("token", "absent", "TOKEN", "X-Flag")), "first response seeds all keywords");
        var firstSnapshot = analyzer.invariantKeywords();
        analyzer.updateWith(HttpResponse.httpResponse("HTTP/1.1 200 OK\r\nX-Flag: yes\r\n\r\ntoken TOKEN"));
        check(analyzer.variantKeywords().equals(Set.of("token")), "counts, not mere presence, determine variation");
        check(analyzer.invariantKeywords().equals(Set.of("absent", "TOKEN", "X-Flag")), "absent keywords have stable zero count");
        check(firstSnapshot.size() == 4, "returned sets are snapshots");
        analyzer.updateWith(HttpResponse.httpResponse("HTTP/1.1 200 OK\r\n\r\ntoken token TOKEN"));
        check(analyzer.variantKeywords().equals(Set.of("token", "X-Flag")), "variants persist and include response headers");
        var independent = api.http().createResponseKeywordsAnalyzer(List.of("token"));
        independent.updateWith(HttpResponse.httpResponse("HTTP/1.1 200 OK\r\n\r\ntoken"));
        check(independent.invariantKeywords().equals(Set.of("token")), "analyzers have independent state");
        var repeated = api.http().createResponseKeywordsAnalyzer(List.of("aa"));
        repeated.updateWith(HttpResponse.httpResponse("HTTP/1.1 200 OK\r\n\r\naaaa"));
        repeated.updateWith(HttpResponse.httpResponse("HTTP/1.1 200 OK\r\n\r\naaaaa"));
        check(repeated.invariantKeywords().equals(Set.of("aa")), "matches are non-overlapping");
        try {
            firstSnapshot.clear();
            throw new AssertionError("returned sets must not be mutable");
        } catch (UnsupportedOperationException expected) { }
        try {
            api.http().createResponseKeywordsAnalyzer(List.of(""));
            throw new AssertionError("empty keywords must be rejected");
        } catch (IllegalArgumentException expected) { }
        try {
            analyzer.updateWith(null);
            throw new AssertionError("null responses must be rejected");
        } catch (NullPointerException expected) { }
        api.logging().logToOutput("keyword analysis regression passed");
    }
}
