// Attribute-based response variation analysis, the object behind
// http().createResponseVariationsAnalyzer (previously UnsupportedOperation-
// Exception; real Burp 2026.11.2 returns an analyzer, see
// docs/parity/2026-11-22-real-burp). The first response seeds every
// AttributeType's extracted value; an attribute whose value later differs
// stays variant. The analyzer retains the first extracted attribute values,
// including body content, but not HttpResponse objects. HTML-derived attributes
// come from one small tag scan of the
// body; header and body extraction are deterministic, not a byte-for-byte
// copy of Burp's internal metrics (INITIAL_CONTENT and LIMITED_BODY_CONTENT
// prefixes are WebProbe's documented choices).
import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.http.message.responses.analysis.AttributeType;
import burp.api.montoya.http.message.responses.analysis.ResponseVariationsAnalyzer;
import java.util.ArrayList;
import java.util.EnumMap;
import java.util.EnumSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.TreeSet;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

final class VariationAnalysis implements ResponseVariationsAnalyzer {
    /** Length of the INITIAL_CONTENT body prefix. */
    private static final int INITIAL_LEN = 256;
    /** Length cap of the LIMITED_BODY_CONTENT value. */
    private static final int LIMITED_LEN = 4096;

    private static final Pattern COMMENT = Pattern.compile("<!--(.*?)-->", Pattern.DOTALL);
    private static final Pattern SCRIPT_STYLE = Pattern.compile("<\\s*(script|style)\\b.*?<\\s*/\\s*\\1\\s*>", Pattern.CASE_INSENSITIVE | Pattern.DOTALL);
    private static final Pattern ANY_TAG = Pattern.compile("<[^>]*>");
    private static final Pattern ATTR = Pattern.compile("([a-zA-Z][a-zA-Z0-9-]*)\\s*=\\s*(?:\"([^\"]*)\"|'([^']*)'|([^\\s>]+))");
    private static final Pattern TITLE = Pattern.compile("<\\s*title\\b[^>]*>(.*?)<\\s*/\\s*title\\s*>", Pattern.CASE_INSENSITIVE | Pattern.DOTALL);
    private static final Pattern HEADER_TAG = Pattern.compile("<\\s*h[1-6]\\b[^>]*>(.*?)<\\s*/\\s*h[1-6]\\s*>", Pattern.CASE_INSENSITIVE | Pattern.DOTALL);
    private static final Pattern ANCHOR = Pattern.compile("<\\s*a\\b[^>]*>(.*?)<\\s*/\\s*a\\s*>", Pattern.CASE_INSENSITIVE | Pattern.DOTALL);
    private static final Pattern BUTTON = Pattern.compile("<\\s*button\\b[^>]*>(.*?)<\\s*/\\s*button\\s*>", Pattern.CASE_INSENSITIVE | Pattern.DOTALL);
    private static final Pattern WORDS = Pattern.compile("\\s+");

    /** One parsed start tag: lowercased name and lowercased-name attributes. */
    private record Tag(String name, Map<String, String> attrs) {}

    private final Map<AttributeType, Object> first = new EnumMap<>(AttributeType.class);
    private final Set<AttributeType> variants = EnumSet.noneOf(AttributeType.class);
    private boolean initialized;

    @Override
    public synchronized Set<AttributeType> variantAttributes() {
        return Set.copyOf(variants);
    }

    @Override
    public synchronized Set<AttributeType> invariantAttributes() {
        if (!initialized) return Set.of();
        EnumSet<AttributeType> all = EnumSet.allOf(AttributeType.class);
        all.removeAll(variants);
        return Set.copyOf(all);
    }

    @Override
    public synchronized void updateWith(HttpResponse response) {
        Objects.requireNonNull(response, "response");
        Map<String, List<String>> headers = new java.util.LinkedHashMap<>();
        for (HttpHeader h : response.headers())
            headers.computeIfAbsent(h.name().toLowerCase(Locale.ROOT), k -> new ArrayList<>()).add(h.value());
        String body = response.bodyToString();
        List<Tag> tags = tags(body);
        for (AttributeType type : AttributeType.values()) {
            if (variants.contains(type)) continue;
            Object value = extract(type, response.statusCode(), headers, body, tags);
            if (!initialized) first.put(type, value);
            else if (!Objects.equals(first.get(type), value)) variants.add(type);
        }
        initialized = true;
    }

    private static Object extract(AttributeType type, int status, Map<String, List<String>> headers, String body, List<Tag> tags) {
        switch (type) {
            case STATUS_CODE: return status;
            case ETAG_HEADER: return header(headers, "etag");
            case LAST_MODIFIED_HEADER: return header(headers, "last-modified");
            case CONTENT_TYPE: {
                String v = header(headers, "content-type");
                int semi = v.indexOf(';');
                return (semi < 0 ? v : v.substring(0, semi)).trim().toLowerCase(Locale.ROOT);
            }
            case CONTENT_LENGTH: return body.length();
            case CONTENT_LOCATION: return header(headers, "content-location");
            case LOCATION: return header(headers, "location");
            case COOKIE_NAMES: {
                Set<String> names = new TreeSet<>();
                for (String v : headers.getOrDefault("set-cookie", List.of())) {
                    int eq = v.indexOf('=');
                    names.add((eq < 0 ? v : v.substring(0, eq)).trim());
                }
                return names;
            }
            case HEADER_NAMES: return new TreeSet<>(headers.keySet());
            case TAG_NAMES: {
                Set<String> names = new TreeSet<>();
                for (Tag t : tags) names.add(t.name());
                return names;
            }
            case TAG_IDS: {
                Set<String> ids = new TreeSet<>();
                for (Tag t : tags) if (t.attrs().containsKey("id")) ids.add(t.attrs().get("id"));
                return ids;
            }
            case DIV_IDS: {
                Set<String> ids = new TreeSet<>();
                for (Tag t : tags) if (t.name().equals("div") && t.attrs().containsKey("id")) ids.add(t.attrs().get("id"));
                return ids;
            }
            case BODY_CONTENT: return body;
            case LIMITED_BODY_CONTENT: return body.substring(0, Math.min(LIMITED_LEN, body.length()));
            case INITIAL_CONTENT: return body.substring(0, Math.min(INITIAL_LEN, body.length()));
            case VISIBLE_TEXT: return visibleText(body);
            case WORD_COUNT: return wordCount(body);
            case VISIBLE_WORD_COUNT: return wordCount(visibleText(body));
            case COMMENTS: {
                List<String> out = new ArrayList<>();
                Matcher m = COMMENT.matcher(body);
                while (m.find()) out.add(m.group(1).trim());
                return out;
            }
            case PAGE_TITLE: return firstGroup(TITLE, body);
            case FIRST_HEADER_TAG: return firstGroup(HEADER_TAG, body);
            case HEADER_TAGS: return allGroups(HEADER_TAG, body);
            case ANCHOR_LABELS: return allGroups(ANCHOR, body);
            case BUTTON_SUBMIT_LABELS: return allGroups(BUTTON, body);
            case INPUT_SUBMIT_LABELS: return inputLabels(tags, "submit");
            case INPUT_IMAGE_LABELS: return inputLabels(tags, "image");
            case NON_HIDDEN_FORM_INPUT_TYPES: {
                List<String> out = new ArrayList<>();
                for (Tag t : tags) {
                    if (!t.name().equals("input")) continue;
                    String kind = t.attrs().getOrDefault("type", "text").toLowerCase(Locale.ROOT);
                    if (!kind.equals("hidden")) out.add(kind);
                }
                return out;
            }
            case CSS_CLASSES: {
                Set<String> classes = new TreeSet<>();
                for (Tag t : tags)
                    for (String c : t.attrs().getOrDefault("class", "").split("\\s+"))
                        if (!c.isEmpty()) classes.add(c);
                return classes;
            }
            case LINE_COUNT: {
                if (body.isEmpty()) return 0;
                int lines = 1;
                for (int i = 0; i < body.length(); i++) if (body.charAt(i) == '\n') lines++;
                return lines;
            }
            case COLON_COUNT: {
                int n = 0;
                for (int i = 0; i < body.length(); i++) if (body.charAt(i) == ':') n++;
                return n;
            }
            case OUTBOUND_EDGE_COUNT: return edgeTags(tags).size();
            case OUTBOUND_EDGE_TAG_NAMES: {
                Set<String> names = new TreeSet<>();
                for (Tag t : edgeTags(tags)) names.add(t.name());
                return names;
            }
            case CANONICAL_LINK: {
                for (Tag t : tags)
                    if (t.name().equals("link") && t.attrs().getOrDefault("rel", "").equalsIgnoreCase("canonical"))
                        return t.attrs().getOrDefault("href", "");
                return "";
            }
            default: return "";
        }
    }

    private static String header(Map<String, List<String>> headers, String name) {
        List<String> v = headers.get(name);
        return v == null || v.isEmpty() ? "" : v.get(0);
    }

    /** Tags carrying an outbound edge: a[href], img/script/iframe[src],
     *  link[href], form[action]. */
    private static List<Tag> edgeTags(List<Tag> tags) {
        List<Tag> out = new ArrayList<>();
        for (Tag t : tags) {
            boolean edge = switch (t.name()) {
                case "a", "link" -> t.attrs().containsKey("href");
                case "img", "script", "iframe" -> t.attrs().containsKey("src");
                case "form" -> t.attrs().containsKey("action");
                default -> false;
            };
            if (edge) out.add(t);
        }
        return out;
    }

    private static List<String> inputLabels(List<Tag> tags, String type) {
        List<String> out = new ArrayList<>();
        for (Tag t : tags) {
            if (!t.name().equals("input")) continue;
            if (!t.attrs().getOrDefault("type", "text").equalsIgnoreCase(type)) continue;
            String label = t.attrs().getOrDefault("value", t.attrs().getOrDefault("alt", ""));
            out.add(label);
        }
        return out;
    }

    private static String visibleText(String body) {
        String noComments = COMMENT.matcher(body).replaceAll(" ");
        String noScripts = SCRIPT_STYLE.matcher(noComments).replaceAll(" ");
        String noTags = ANY_TAG.matcher(noScripts).replaceAll(" ");
        return noTags.replaceAll("\\s+", " ").trim();
    }

    private static int wordCount(String text) {
        String t = text.trim();
        return t.isEmpty() ? 0 : WORDS.split(t).length;
    }

    private static String firstGroup(Pattern p, String body) {
        Matcher m = p.matcher(body);
        return m.find() ? m.group(1).trim() : "";
    }

    private static List<String> allGroups(Pattern p, String body) {
        List<String> out = new ArrayList<>();
        Matcher m = p.matcher(body);
        while (m.find()) out.add(m.group(1).trim());
        return out;
    }

    private static List<Tag> tags(String body) {
        List<Tag> out = new ArrayList<>();
        // Scan start tags without recursive regular-expression repetition:
        // long unquoted attribute values must not overflow the JVM stack.
        int cursor = 0;
        while (cursor < body.length()) {
            int open = body.indexOf('<', cursor);
            if (open < 0) break;
            int start = open + 1;
            while (start < body.length() && Character.isWhitespace(body.charAt(start))) start++;
            int nameEnd = start;
            while (nameEnd < body.length()) {
                char c = body.charAt(nameEnd);
                if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
                        || (nameEnd > start && c >= '0' && c <= '9'))) break;
                nameEnd++;
            }
            if (nameEnd == start) { cursor = start + 1; continue; }
            int end = nameEnd;
            char quote = 0;
            for (; end < body.length(); end++) {
                char c = body.charAt(end);
                if (quote != 0) { if (c == quote) quote = 0; }
                else if (c == '\'' || c == '"') quote = c;
                else if (c == '>') break;
            }
            if (end == body.length()) break;
            Map<String, String> attrs = new java.util.LinkedHashMap<>();
            Matcher a = ATTR.matcher(body.substring(nameEnd, end));
            while (a.find()) {
                String v = a.group(2) != null ? a.group(2) : a.group(3) != null ? a.group(3) : a.group(4);
                attrs.put(a.group(1).toLowerCase(Locale.ROOT), v == null ? "" : v);
            }
            out.add(new Tag(body.substring(start, nameEnd).toLowerCase(Locale.ROOT), attrs));
            cursor = end + 1;
        }
        return out;
    }
}
