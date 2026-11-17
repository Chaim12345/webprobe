// MontoyaBridge.java — Path B sidecar JVM bridge (wave 30).
// Loads a real Burp Montoya extension (.jar) against Burp's own Montoya API
// (from /opt/BurpSuite/burpsuite.jar) and exposes its Proxy request/response
// handlers to WebProbe over a JSON-lines protocol on stdin/stdout.
//
// Launch (single-file source mode, no build step):
//   java -cp /opt/BurpSuite/burpsuite.jar MontoyaBridge.java <ext.jar>
//
// Protocol (one JSON object per line):
//   -> {"type":"ping"}                          => {"type":"pong"}
//   -> {"type":"request","id":N,"method":"GET","path":"/x",
//       "headers":[["Host","a.com"]],"body":"...","url":"...",
//       "host":"a.com","port":80,"secure":false,"httpVersion":"HTTP/1.1"}
//      => {"id":N,"action":"continue"|"drop"}
//         plus, when a handler continued with an edited message
//         (withAddedHeader / withBody / withMethod ...):
//         "edited":true,"method","path","httpVersion","headers","body"
//   -> {"type":"response","id":N,"status":200,"reason":"OK",...same}
//      => {"id":N,"action":"continue"|"drop"}  (+ "edited", "status",
//         "reason", "headers", "body" for an edited response)
//   -> {"type":"shutdown"}                      (bridge exits 0)
//
// stdout carries ONLY protocol replies; extension logging goes to stderr.
//
// Honest v1 scope (documented in qa/SOURCE-PARITY-2026-11-15.md):
//  - extensions load, initialize, log, continue or drop messages, and edit
//    them with the immutable with* methods (headers, body, method, path,
//    status, reason); handlers see the previous handler's edits;
//  - UI-related APIs (http(), burpSuite(), collaborator(), utilities())
//    throw UnsupportedOperationException — WebProbe has no matching UI;
//  - only handleRequestReceived / handleResponseReceived are invoked
//    (matching WebProbe's ProxyHooks surface), not the *ToBeSent halves.

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.Annotations;
import burp.api.montoya.core.HighlightColor;
import burp.api.montoya.core.Registration;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.internal.MontoyaObjectFactory;
import burp.api.montoya.internal.ObjectFactoryLocator;
import burp.api.montoya.logging.Logging;
import burp.api.montoya.proxy.MessageReceivedAction;
import burp.api.montoya.proxy.http.InterceptedRequest;
import burp.api.montoya.proxy.http.InterceptedResponse;
import burp.api.montoya.proxy.http.ProxyRequestHandler;
import burp.api.montoya.proxy.http.ProxyRequestReceivedAction;
import burp.api.montoya.proxy.http.ProxyResponseHandler;
import burp.api.montoya.proxy.http.ProxyResponseReceivedAction;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.PrintStream;
import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;
import java.net.URL;
import java.net.URLClassLoader;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.ServiceLoader;

public class MontoyaBridge {

    // ---------- message state ----------

    static final class MsgState {
        String type = "request";
        int id;
        String method = "GET";
        String path = "/";
        String url = "";
        String host = "";
        int port = 80;
        boolean secure = false;
        String httpVersion = "HTTP/1.1";
        int status = 200;
        String reason = "OK";
        String body = "";
        List<String[]> headers = new ArrayList<>();
        boolean edited = false;

        MsgState copy() {
            MsgState c = new MsgState();
            c.type = type; c.id = id; c.method = method; c.path = path; c.url = url; c.host = host;
            c.port = port; c.secure = secure; c.httpVersion = httpVersion; c.status = status;
            c.reason = reason; c.body = body; c.edited = true;
            for (String[] h : headers) c.headers.add(new String[] { h[0], h[1] });
            return c;
        }
    }

    /// Header (name, value) from a with* argument: (String, String) or an HttpHeader.
    static String[] headerArg(Object[] a) {
        if (a.length >= 2) return new String[] { String.valueOf(a[0]), String.valueOf(a[1]) };
        HttpHeader h = (HttpHeader) a[0];
        return new String[] { h.name(), h.value() };
    }

    /// The state behind one of our message stubs, or null for a foreign object.
    static MsgState stateOfStub(Object o) {
        if (o != null && Proxy.isProxyClass(o.getClass()) && Proxy.getInvocationHandler(o) instanceof MsgStub ms) return ms.s;
        return null;
    }

    static final class MsgStub implements InvocationHandler {
        final MsgState s;
        MsgStub(MsgState s) { this.s = s; }

        static Object newStub(MsgState s) {
            Class<?> iface = s.type.equals("request") ? InterceptedRequest.class : InterceptedResponse.class;
            return Proxy.newProxyInstance(MontoyaBridge.class.getClassLoader(),
                    new Class<?>[] { iface }, new MsgStub(s));
        }

        @Override public Object invoke(Object proxy, Method m, Object[] args) {
            // Immutable edits: each with* returns a new message.
            switch (m.getName()) {
                case "withAddedHeader": { MsgState c = s.copy(); c.headers.add(headerArg(args)); return newStub(c); }
                case "withUpdatedHeader": case "withHeader": {
                    MsgState c = s.copy(); String[] h = headerArg(args); boolean found = false;
                    for (String[] x : c.headers) if (x[0].equalsIgnoreCase(h[0])) { x[1] = h[1]; found = true; }
                    if (!found && m.getName().equals("withHeader")) c.headers.add(h);
                    return newStub(c);
                }
                case "withRemovedHeader": {
                    MsgState c = s.copy();
                    String name = args[0] instanceof HttpHeader hh ? hh.name() : String.valueOf(args[0]);
                    c.headers.removeIf(x -> x[0].equalsIgnoreCase(name));
                    return newStub(c);
                }
                case "withBody": { MsgState c = s.copy(); c.body = String.valueOf(args[0]); return newStub(c); }
                case "withMethod": { MsgState c = s.copy(); c.method = String.valueOf(args[0]); return newStub(c); }
                case "withPath": { MsgState c = s.copy(); c.path = String.valueOf(args[0]); return newStub(c); }
                case "withStatusCode": { MsgState c = s.copy(); c.status = ((Number) args[0]).intValue(); return newStub(c); }
                case "withReasonPhrase": { MsgState c = s.copy(); c.reason = String.valueOf(args[0]); return newStub(c); }
                default: break;
            }
            switch (m.getName()) {
                case "method": return s.method;
                case "path": case "pathWithoutQuery": return s.path;
                case "url": return s.url;
                case "httpVersion": return s.httpVersion;
                case "headers": {
                    List<HttpHeader> out = new ArrayList<>();
                    for (String[] h : s.headers) {
                        out.add((HttpHeader) Proxy.newProxyInstance(getClass().getClassLoader(),
                                new Class<?>[] { HttpHeader.class },
                                (p, mm, a) -> mm.getName().equals("name") ? h[0]
                                        : mm.getName().equals("value") ? h[1] : dflt(mm)));
                    }
                    return out;
                }
                case "headerValue": {
                    String want = String.valueOf(args[0]);
                    for (String[] h : s.headers)
                        if (h[0].equalsIgnoreCase(want)) return h[1];
                    return null;
                }
                case "hasHeader": {
                    String want = String.valueOf(args[0]);
                    for (String[] h : s.headers)
                        if (h[0].equalsIgnoreCase(want)) return true;
                    return false;
                }
                case "bodyToString": return s.body;
                case "httpService": {
                    return Proxy.newProxyInstance(getClass().getClassLoader(),
                            new Class<?>[] { HttpService.class },
                            (p, mm, a) -> mm.getName().equals("host") ? s.host
                                    : mm.getName().equals("port") ? s.port
                                    : mm.getName().equals("secure") ? s.secure : dflt(mm));
                }
                case "messageId": return s.id;
                case "statusCode": return (short) s.status;
                case "status": return s.status;
                case "reasonPhrase": return s.reason;
                case "toString": return s.type.equals("request")
                        ? s.method + " " + s.path + " " + s.httpVersion
                        : s.httpVersion + " " + s.status + " " + s.reason;
                case "hashCode": return System.identityHashCode(proxy);
                default: return dflt(m);
            }
        }

        static Object dflt(Method m) {
            Class<?> r = m.getReturnType();
            if (r == String.class) return "";
            if (r == int.class || r == long.class) return 0;
            if (r == boolean.class) return false;
            if (r == List.class) return List.of();
            throw new UnsupportedOperationException("MontoyaBridge: " + m.getName() + " is not supported in v1");
        }
    }

    // ---------- MontoyaObjectFactory (drives ProxyRequestReceivedAction.drop() etc.) ----------

    static final class FactoryStub implements InvocationHandler {
        @Override public Object invoke(Object proxy, Method m, Object[] args) {
            String n = m.getName();
            boolean drop = n.endsWith("Drop");
            boolean requestSide = n.startsWith("request");
            Object message = (args != null && args.length > 0) ? args[0] : null;
            return newAction(drop ? MessageReceivedAction.DROP : MessageReceivedAction.CONTINUE, message, requestSide);
        }
    }

    static Object newAction(MessageReceivedAction act, Object message, boolean requestSide) {
        Class<?> iface = requestSide ? ProxyRequestReceivedAction.class : ProxyResponseReceivedAction.class;
        return Proxy.newProxyInstance(MontoyaBridge.class.getClassLoader(),
                new Class<?>[] { iface },
                (p, m, a) -> {
                    switch (m.getName()) {
                        case "action": return act;
                        case "request": case "response": return message;
                        case "annotations": return newAnnotations();
                        case "toString": return act + "(" + message + ")";
                        default: return MsgStub.dflt(m);
                    }
                });
    }

    static Object newAnnotations() {
        return Proxy.newProxyInstance(MontoyaBridge.class.getClassLoader(),
                new Class<?>[] { Annotations.class },
                (p, m, a) -> m.getName().equals("notes") ? ""
                        : m.getName().equals("highlightColor") ? HighlightColor.NONE
                        : MsgStub.dflt(m));
    }

    // ---------- MontoyaApi ----------

    static final List<ProxyRequestHandler> REQ_HANDLERS = new ArrayList<>();
    static final List<ProxyResponseHandler> RESP_HANDLERS = new ArrayList<>();

    static Object newRegistration() {
        return Proxy.newProxyInstance(MontoyaBridge.class.getClassLoader(),
                new Class<?>[] { Registration.class },
                (p, m, a) -> { /* deregister() is a no-op for the sidecar lifetime */ return null; });
    }

    static Object newProxyApi() {
        return Proxy.newProxyInstance(MontoyaBridge.class.getClassLoader(),
                new Class<?>[] { burp.api.montoya.proxy.Proxy.class },
                (p, m, a) -> {
                    switch (m.getName()) {
                        case "registerRequestHandler":
                            REQ_HANDLERS.add((ProxyRequestHandler) a[0]);
                            return newRegistration();
                        case "registerResponseHandler":
                            RESP_HANDLERS.add((ProxyResponseHandler) a[0]);
                            return newRegistration();
                        case "enableIntercept": case "disableIntercept":
                            return null; // no interception UI on the sidecar
                        default:
                            throw new UnsupportedOperationException("MontoyaBridge: Proxy." + m.getName() + " is not supported in v1");
                    }
                });
    }

    static Object newLogging() {
        return Proxy.newProxyInstance(MontoyaBridge.class.getClassLoader(),
                new Class<?>[] { Logging.class },
                (p, m, a) -> {
                    StringBuilder msg = new StringBuilder("[ext] " + m.getName());
                    if (a != null) for (Object o : a) msg.append(": ").append(o);
                    System.err.println(msg);
                    return null;
                });
    }

    static Object newApi() {
        return Proxy.newProxyInstance(MontoyaBridge.class.getClassLoader(),
                new Class<?>[] { MontoyaApi.class },
                (p, m, a) -> {
                    switch (m.getName()) {
                        case "proxy": return newProxyApi();
                        case "logging": return newLogging();
                        default:
                            throw new UnsupportedOperationException("MontoyaBridge: MontoyaApi." + m.getName()
                                    + " is not supported in v1 (no Burp UI on the sidecar)");
                    }
                });
    }

    // ---------- minimal JSON ----------

    static final class Json {
        String s; int i;
        Json(String s) { this.s = s; }
        static Object parse(String text) { Json j = new Json(text); j.ws(); return j.value(); }
        void ws() { while (i < s.length() && Character.isWhitespace(s.charAt(i))) i++; }
        char peek() { return s.charAt(i); }
        Object value() {
            ws();
            char c = peek();
            switch (c) {
                case '{': return obj();
                case '[': return arr();
                case '"': return str();
                case 't': i += 4; return Boolean.TRUE;
                case 'f': i += 5; return Boolean.FALSE;
                case 'n': i += 4; return null;
                default: return num();
            }
        }
        Map<String, Object> obj() {
            Map<String, Object> m = new HashMap<>();
            i++; ws();
            if (peek() == '}') { i++; return m; }
            while (true) {
                ws();
                String k = str();
                ws(); expect(':');
                m.put(k, value());
                ws();
                char c = s.charAt(i++);
                if (c == '}') return m;
                if (c != ',') throw new IllegalArgumentException("bad object at " + i);
            }
        }
        List<Object> arr() {
            List<Object> l = new ArrayList<>();
            i++; ws();
            if (peek() == ']') { i++; return l; }
            while (true) {
                l.add(value());
                ws();
                char c = s.charAt(i++);
                if (c == ']') return l;
                if (c != ',') throw new IllegalArgumentException("bad array at " + i);
            }
        }
        String str() {
            expect('"');
            StringBuilder b = new StringBuilder();
            while (true) {
                char c = s.charAt(i++);
                if (c == '"') return b.toString();
                if (c == '\\') {
                    char e = s.charAt(i++);
                    switch (e) {
                        case 'n': b.append('\n'); break;
                        case 't': b.append('\t'); break;
                        case 'r': b.append('\r'); break;
                        case 'b': b.append('\b'); break;
                        case 'f': b.append('\f'); break;
                        case 'u': b.append((char) Integer.parseInt(s.substring(i, i + 4), 16)); i += 4; break;
                        default: b.append(e);
                    }
                } else b.append(c);
            }
        }
        double num() {
            int start = i;
            while (i < s.length() && "-+.eE0123456789".indexOf(s.charAt(i)) >= 0) i++;
            return Double.parseDouble(s.substring(start, i));
        }
        void expect(char c) {
            if (i >= s.length() || s.charAt(i) != c)
                throw new IllegalArgumentException("expected '" + c + "' at " + i);
            i++;
        }
        static String esc(String v) {
            StringBuilder b = new StringBuilder("\"");
            for (int k = 0; k < v.length(); k++) {
                char c = v.charAt(k);
                switch (c) {
                    case '"': b.append("\\\""); break;
                    case '\\': b.append("\\\\"); break;
                    case '\n': b.append("\\n"); break;
                    case '\r': b.append("\\r"); break;
                    case '\t': b.append("\\t"); break;
                    default:
                        if (c < 0x20) b.append(String.format("\\u%04x", (int) c));
                        else b.append(c);
                }
            }
            return b.append('"').toString();
        }
    }

    @SuppressWarnings("unchecked")
    static String[] headerPair(Object o) {
        List<Object> l = (List<Object>) o;
        return new String[] { String.valueOf(l.get(0)), String.valueOf(l.get(1)) };
    }

    static MsgState stateOf(Map<String, Object> m) {
        MsgState s = new MsgState();
        s.type = String.valueOf(m.getOrDefault("type", "request"));
        s.id = (int) doubleOf(m.get("id"));
        s.method = String.valueOf(m.getOrDefault("method", "GET"));
        s.path = String.valueOf(m.getOrDefault("path", "/"));
        s.url = String.valueOf(m.getOrDefault("url", ""));
        s.host = String.valueOf(m.getOrDefault("host", ""));
        s.port = (int) doubleOf(m.getOrDefault("port", 80));
        s.secure = Boolean.TRUE.equals(m.get("secure"));
        s.httpVersion = String.valueOf(m.getOrDefault("httpVersion", "HTTP/1.1"));
        s.status = (int) doubleOf(m.getOrDefault("status", 200));
        s.reason = String.valueOf(m.getOrDefault("reason", "OK"));
        s.body = String.valueOf(m.getOrDefault("body", ""));
        Object hs = m.get("headers");
        if (hs instanceof List<?>)
            for (Object o : (List<Object>) hs) s.headers.add(headerPair(o));
        return s;
    }

    static double doubleOf(Object o) {
        return o instanceof Number ? ((Number) o).doubleValue() : 0;
    }

    // ---------- main loop ----------

    public static void main(String[] args) throws Exception {
        // Replies go to the real stdout only. Extensions printing with
        // System.out would otherwise put lines into the reply stream, and
        // WebProbe would apply one message's verdict to the next.
        PrintStream out = new PrintStream(new java.io.FileOutputStream(java.io.FileDescriptor.out), true, StandardCharsets.UTF_8);
        System.setOut(System.err);
        if (args.length < 1) {
            System.err.println("usage: java -cp burpsuite.jar MontoyaBridge.java <ext.jar>");
            System.exit(2);
        }
        ObjectFactoryLocator.FACTORY = (MontoyaObjectFactory) Proxy.newProxyInstance(
                MontoyaBridge.class.getClassLoader(),
                new Class<?>[] { MontoyaObjectFactory.class }, new FactoryStub());

        URLClassLoader cl = new URLClassLoader(new URL[] { new URL("file:" + args[0]) });
        MontoyaApi api = (MontoyaApi) newApi();
        boolean loaded = false;
        for (BurpExtension ext : ServiceLoader.load(BurpExtension.class, cl)) {
            System.err.println("[bridge] initializing extension " + ext.getClass().getName());
            ext.initialize(api);
            loaded = true;
        }
        if (!loaded) {
            System.err.println("[bridge] no burp.api.montoya.BurpExtension implementation found in " + args[0]);
            System.exit(2);
        }
        System.err.println("[bridge] ready (" + REQ_HANDLERS.size() + " request handlers, "
                + RESP_HANDLERS.size() + " response handlers)");

        BufferedReader in = new BufferedReader(new InputStreamReader(System.in, StandardCharsets.UTF_8));
        String line;
        while ((line = in.readLine()) != null) {
            if (line.isBlank()) continue;
            Map<String, Object> msg = (Map<String, Object>) Json.parse(line);
            String type = String.valueOf(msg.get("type"));
            if (type.equals("ping")) { out.println("{\"type\":\"pong\"}"); continue; }
            if (type.equals("shutdown")) break;
            if (!type.equals("request") && !type.equals("response")) continue;

            MsgState state = stateOf(msg);
            boolean drop = false;
            final MsgState original = state;
            try {
            // Each handler gets the message as the previous one left it.
            if (type.equals("request")) {
                for (ProxyRequestHandler h : REQ_HANDLERS) {
                    InterceptedRequest stub = (InterceptedRequest) MsgStub.newStub(state);
                    ProxyRequestReceivedAction act = h.handleRequestReceived(stub);
                    if (act != null && act.action() == MessageReceivedAction.DROP) { drop = true; break; }
                    MsgState next = act == null ? null : stateOfStub(act.request());
                    if (next != null) state = next;
                }
            } else {
                for (ProxyResponseHandler h : RESP_HANDLERS) {
                    InterceptedResponse stub = (InterceptedResponse) MsgStub.newStub(state);
                    ProxyResponseReceivedAction act = h.handleResponseReceived(stub);
                    if (act != null && act.action() == MessageReceivedAction.DROP) { drop = true; break; }
                    MsgState next = act == null ? null : stateOfStub(act.response());
                    if (next != null) state = next;
                }
            }
            } catch (Throwable t) {
                // One failing handler must not end the bridge for every later
                // message: report it and let this message through unchanged.
                System.err.println("[bridge] handler failed on message " + original.id + ": " + t);
                state = original;
                drop = false;
            }
            StringBuilder reply = new StringBuilder("{\"id\":" + state.id + ",\"action\":\"" + (drop ? "drop" : "continue") + "\"");
            if (!drop && state.edited) {
                reply.append(",\"edited\":true,\"method\":").append(Json.esc(state.method))
                        .append(",\"path\":").append(Json.esc(state.path))
                        .append(",\"httpVersion\":").append(Json.esc(state.httpVersion))
                        .append(",\"status\":").append(state.status)
                        .append(",\"reason\":").append(Json.esc(state.reason))
                        .append(",\"body\":").append(Json.esc(state.body))
                        .append(",\"headers\":[");
                for (int k = 0; k < state.headers.size(); k++) {
                    String[] h = state.headers.get(k);
                    if (k > 0) reply.append(',');
                    reply.append('[').append(Json.esc(h[0])).append(',').append(Json.esc(h[1])).append(']');
                }
                reply.append(']');
            }
            out.println(reply.append('}'));
        }
        out.flush();
    }
}
