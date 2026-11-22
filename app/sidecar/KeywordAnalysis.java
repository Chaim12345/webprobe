// Literal, case-sensitive keyword counts over the complete HTTP response.
// Each analyzer retains only one count per keyword and the variant set,
// never the responses. Counts use non-overlapping matches.
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.http.message.responses.analysis.ResponseKeywordsAnalyzer;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

final class KeywordAnalysis implements ResponseKeywordsAnalyzer {
    private final Map<String, Integer> firstCounts = new LinkedHashMap<>();
    private final Set<String> variants = new LinkedHashSet<>();
    private boolean initialized;

    KeywordAnalysis(List<String> keywords) {
        for (String keyword : List.copyOf(keywords)) {
            if (keyword.isEmpty()) throw new IllegalArgumentException("Keyword must not be empty");
            firstCounts.put(keyword, 0);
        }
    }

    @Override
    public synchronized Set<String> variantKeywords() {
        return Set.copyOf(variants);
    }

    @Override
    public synchronized Set<String> invariantKeywords() {
        if (!initialized) return Set.of();
        Set<String> result = new LinkedHashSet<>(firstCounts.keySet());
        result.removeAll(variants);
        return Set.copyOf(result);
    }

    @Override
    public synchronized void updateWith(HttpResponse response) {
        String raw = Objects.requireNonNull(response, "response").toString();
        for (Map.Entry<String, Integer> entry : firstCounts.entrySet()) {
            if (variants.contains(entry.getKey())) continue;
            int count = count(raw, entry.getKey());
            if (!initialized) entry.setValue(count);
            else if (count != entry.getValue()) variants.add(entry.getKey());
        }
        initialized = true;
    }

    private static int count(String text, String keyword) {
        int count = 0;
        for (int start = 0, match; (match = text.indexOf(keyword, start)) >= 0; start = match + keyword.length()) count++;
        return count;
    }
}
