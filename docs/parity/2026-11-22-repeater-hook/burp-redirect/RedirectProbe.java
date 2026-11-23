import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.handler.*;
import java.nio.file.*;
public class RedirectProbe implements BurpExtension {
 private MontoyaApi api;
 private synchronized void log(String s) {
  api.logging().logToOutput(s);
  try { Files.writeString(Path.of("/downloads/burp-comparison/redirect/handler.log"),s+"\n",StandardOpenOption.CREATE,StandardOpenOption.APPEND); }
  catch(Exception e){api.logging().logToError(e.toString());}
 }
 private long count(HttpRequest r){return r.headers().stream().filter(h->h.name().equalsIgnoreCase("X-Parity-Probe")).count();}
 public void initialize(MontoyaApi a) {
  api=a;api.extension().setName("Local redirect handler probe");
  api.http().registerHttpHandler(new HttpHandler(){
   public RequestToBeSentAction handleHttpRequestToBeSent(HttpRequestToBeSent r){
    var modified=r.withAddedHeader("X-Parity-Probe","1");
    log("request\tid="+r.messageId()+"\ttool="+r.toolSource().toolType().name()+"\tpath="+r.path()+"\tincoming="+count(r)+"\toutgoing="+count(modified));
    return RequestToBeSentAction.continueWith(modified);
   }
   public ResponseReceivedAction handleHttpResponseReceived(HttpResponseReceived r){
    log("response\tid="+r.messageId()+"\ttool="+r.toolSource().toolType().name()+"\tstatus="+r.statusCode());
    return ResponseReceivedAction.continueWith(r);
   }
  });
  api.repeater().sendToRepeater(HttpRequest.httpRequestFromUrl("http://127.0.0.1:18767/start"),"Redirect parity");
  log("initialized");
 }
}
