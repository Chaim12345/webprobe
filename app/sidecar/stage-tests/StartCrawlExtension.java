// R-20: Scanner.startCrawl through the public Montoya API. The seed URL
// is the one Proxy history item the test provides. A purpose-built test
// extension, not evidence of unmodified BApp parity.
import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.scanner.Crawl;
import burp.api.montoya.scanner.CrawlConfiguration;

public class StartCrawlExtension implements BurpExtension {
    @Override
    public void initialize(MontoyaApi api) {
        api.extension().setName("startCrawl regression");
        // The test puts one item in Proxy history; its URL is the seed.
        String seed = api.proxy().history().get(0).finalRequest().url();
        Crawl crawl = api.scanner().startCrawl(CrawlConfiguration.crawlConfiguration(seed));
        api.logging().logToError("crawl started: " + crawl.statusMessage());
        Thread watch = new Thread(() -> {
            try {
                for (int i = 0; i < 100 && !"Crawl finished".equals(crawl.statusMessage()); i++) Thread.sleep(100);
                api.logging().logToError("crawl status: " + crawl.statusMessage() + " items=" + crawl.requestCount() + " errors=" + crawl.errorCount());
                crawl.delete();
                api.logging().logToError("crawl after delete: " + crawl.statusMessage());
            } catch (Throwable t) {
                api.logging().logToError("crawl watch failed: " + t);
            }
        }, "crawl-watch");
        watch.setDaemon(true);
        watch.start();
    }
}
