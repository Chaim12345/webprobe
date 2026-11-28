// R-20: websockets().createWebSocket through the public Montoya API,
// against a one-connection echo server this extension runs itself.
// A purpose-built test extension, not evidence of unmodified BApp parity.
import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.websocket.BinaryMessage;
import burp.api.montoya.websocket.TextMessage;
import burp.api.montoya.websocket.extension.ExtensionWebSocketCreationStatus;
import burp.api.montoya.websocket.extension.ExtensionWebSocketMessageHandler;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Base64;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;

public class CreateWebSocketExtension implements BurpExtension {
    private static void check(boolean ok, String message) {
        if (!ok) throw new AssertionError(message);
    }

    /** Accept one client, do the handshake, echo every data frame. */
    private static void serve(ServerSocket server) {
        try (Socket s = server.accept()) {
            InputStream in = s.getInputStream();
            OutputStream out = s.getOutputStream();
            StringBuilder head = new StringBuilder();
            while (!head.toString().endsWith("\r\n\r\n")) { int c = in.read(); if (c < 0) return; head.append((char) c); }
            String key = null;
            for (String line : head.toString().split("\r\n"))
                if (line.toLowerCase().startsWith("sec-websocket-key:")) key = line.substring(line.indexOf(':') + 1).trim();
            String accept = Base64.getEncoder().encodeToString(MessageDigest.getInstance("SHA-1")
                    .digest((key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11").getBytes(StandardCharsets.US_ASCII)));
            out.write(("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: " + accept + "\r\n\r\n").getBytes(StandardCharsets.US_ASCII));
            out.flush();
            while (true) {
                int b0 = in.read(), b1 = in.read();
                if (b0 < 0 || b1 < 0) return;
                int opcode = b0 & 0x0f, len = b1 & 0x7f;
                byte[] mask = in.readNBytes(4);
                byte[] data = in.readNBytes(len);
                for (int i = 0; i < data.length; i++) data[i] ^= mask[i % 4];
                if (opcode == 8) { out.write(new byte[] { (byte) 0x88, 0 }); out.flush(); return; }
                out.write(new byte[] { (byte) (0x80 | opcode), (byte) data.length });
                out.write(data);
                out.flush();
            }
        } catch (Exception e) {
            // The test fails on the client side if the server did not answer.
        }
    }

    @Override
    public void initialize(MontoyaApi api) {
        api.extension().setName("createWebSocket regression");
        try {
            ServerSocket server = new ServerSocket(0, 1, java.net.InetAddress.getLoopbackAddress());
            int port = server.getLocalPort();
            Thread t = new Thread(() -> serve(server), "ws-echo");
            t.setDaemon(true);
            t.start();
            var creation = api.websockets().createWebSocket(HttpService.httpService("127.0.0.1", port, false), "/echo");
            check(creation.status() == ExtensionWebSocketCreationStatus.SUCCESS, "connected: " + creation.status());
            var socket = creation.webSocket().orElseThrow();
            LinkedBlockingQueue<String> seen = new LinkedBlockingQueue<>();
            var registration = socket.registerMessageHandler(new ExtensionWebSocketMessageHandler() {
                @Override public void textMessageReceived(TextMessage m) { seen.add("text:" + m.payload()); }
                @Override public void binaryMessageReceived(BinaryMessage m) { seen.add("binary:" + m.payload().length()); }
                @Override public void onClose() { seen.add("closed"); }
            });
            check(registration.isRegistered(), "handler registered");
            socket.sendTextMessage("ping");
            check("text:ping".equals(seen.poll(5, TimeUnit.SECONDS)), "text frame echoed");
            socket.sendBinaryMessage(ByteArray.byteArray(new byte[] { 0, (byte) 0xff, 7 }));
            check("binary:3".equals(seen.poll(5, TimeUnit.SECONDS)), "binary frame echoed");
            socket.close();
            check("closed".equals(seen.poll(5, TimeUnit.SECONDS)), "close reaches the handler");
            server.close();
            var refused = api.websockets().createWebSocket(HttpService.httpService("127.0.0.1", port, false), "/gone");
            check(refused.status() == ExtensionWebSocketCreationStatus.CONNECTION_FAILED && refused.webSocket().isEmpty(), "a closed port fails: " + refused.status());
            var badPort = api.websockets().createWebSocket(HttpService.httpService("127.0.0.1", 0, false), "/");
            check(badPort.status() == ExtensionWebSocketCreationStatus.INVALID_PORT, "port 0: " + badPort.status());
            api.logging().logToError("createWebSocket regression passed");
        } catch (Exception e) {
            throw new AssertionError(e);
        }
    }
}
