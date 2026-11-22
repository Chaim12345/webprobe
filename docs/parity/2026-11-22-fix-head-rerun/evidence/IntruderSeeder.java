import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.intruder.HttpRequestTemplate;
import burp.api.montoya.core.Range;
import java.util.List;
public class IntruderSeeder implements BurpExtension {
 public void initialize(MontoyaApi api) {
  api.extension().setName("Local Intruder fixture seeder");
  var r=HttpRequest.httpRequestFromUrl("http://127.0.0.1:18765/echo?value=probe");
  int s=r.toString().indexOf("probe");
  api.intruder().sendToIntruder(r.httpService(),HttpRequestTemplate.httpRequestTemplate(r.toByteArray(),List.of(Range.range(s,s+5))));
 }
}
