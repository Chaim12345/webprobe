// DemoExtension.java — a real Montoya extension used to verify the Path B
// sidecar bridge end-to-end. Drops any request whose path contains
// "/admin-drop", adds an X-Montoya-Demo header to every other request and
// an X-Montoya-Seen header to responses, and logs every hook run.
//
// Built (see build-demo-ext.sh) into demo-ext.jar with a
// META-INF/services/burp.api.montoya.BurpExtension registration so
// ServiceLoader finds it, exactly as Burp loads .jar extensions.

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.proxy.http.InterceptedRequest;
import burp.api.montoya.proxy.http.InterceptedResponse;
import burp.api.montoya.proxy.http.ProxyRequestHandler;
import burp.api.montoya.proxy.http.ProxyRequestReceivedAction;
import burp.api.montoya.proxy.http.ProxyRequestToBeSentAction;
import burp.api.montoya.proxy.http.ProxyResponseHandler;
import burp.api.montoya.proxy.http.ProxyResponseReceivedAction;
import burp.api.montoya.proxy.http.ProxyResponseToBeSentAction;

public class DemoExtension implements BurpExtension, ProxyRequestHandler, ProxyResponseHandler {

    @Override
    public void initialize(MontoyaApi api) {
        api.logging().logToOutput("DemoExtension initializing: registering Proxy handlers");
        api.proxy().registerRequestHandler(this);
        api.proxy().registerResponseHandler(this);
        api.logging().logToOutput("DemoExtension ready (ProxyRequestHandler + ProxyResponseHandler)");
    }

    @Override
    public ProxyRequestReceivedAction handleRequestReceived(InterceptedRequest request) {
        apiLog("request hook: " + request.method() + " " + request.path()
                + " host=" + request.httpService().host()
                + " headers=" + request.headers().size());
        if (request.path().contains("/admin-drop")) {
            apiLog("dropping " + request.path());
            return ProxyRequestReceivedAction.drop();
        }
        return ProxyRequestReceivedAction.continueWith(request.withAddedHeader("X-Montoya-Demo", "1"));
    }

    @Override
    public ProxyRequestToBeSentAction handleRequestToBeSent(InterceptedRequest request) {
        // Not invoked by the sidecar bridge (v1 scope: only the *Received halves
        // run, matching WebProbe's ProxyHooks surface). Implemented to satisfy
        // the full Montoya interface.
        return ProxyRequestToBeSentAction.continueWith(request);
    }

    @Override
    public ProxyResponseReceivedAction handleResponseReceived(InterceptedResponse response) {
        apiLog("response hook: " + response.statusCode() + " " + response.reasonPhrase());
        return ProxyResponseReceivedAction.continueWith(response.withAddedHeader("X-Montoya-Seen", "1"));
    }

    @Override
    public ProxyResponseToBeSentAction handleResponseToBeSent(InterceptedResponse response) {
        return ProxyResponseToBeSentAction.continueWith(response);
    }

    private void apiLog(String message) {
        System.err.println("[demo-ext] " + message);
    }
}
