package com.proxyvpn.app;

import android.net.VpnService;
import java.io.ByteArrayOutputStream;
import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;

/** All external connections are VpnService.protect()-ed BEFORE connecting. */
final class ProxyTransport {
    private final VpnService vpn;
    private final ProxyConfig cfg;
    ProxyTransport(VpnService vpn, ProxyConfig cfg) { this.vpn = vpn; this.cfg = cfg; }

    Socket connect(String host, int port) throws IOException {
        Socket upstream = openProxy();
        try {
            if (cfg.mode == ProxyConfig.Mode.SOCKS5) socks(upstream, host, port, 1);
            else httpConnect(upstream, host, port);
            upstream.setSoTimeout(0);
            return upstream;
        } catch (IOException | RuntimeException e) { try { upstream.close(); } catch (IOException ignored) {} throw e; }
    }
    UdpAssociation associate() throws IOException {
        if (cfg.mode != ProxyConfig.Mode.SOCKS5) throw new IOException("SOCKS5 UDP only");
        Socket s = openProxy();
        try {
            Reply r = socks(s, "0.0.0.0", 0, 3);
            String relayHost = r.host.equals("0.0.0.0") ? cfg.host : r.host;
            return new UdpAssociation(s, relayHost, r.port);
        } catch (IOException e) { try { s.close(); } catch (IOException ignored) {} throw e; }
    }
    private Socket openProxy() throws IOException {
        Socket plain = new Socket();
        if (!vpn.protect(plain)) { plain.close(); throw new IOException("Cannot protect proxy socket from VPN loop"); }
        try {
            plain.connect(new InetSocketAddress(cfg.host, cfg.port), 10000);
            plain.setSoTimeout(12000);
            if (cfg.mode != ProxyConfig.Mode.HTTPS) return plain;
            // Validate the proxy's TLS certificate; never silently trust invalid certificates.
            SSLSocket tls = (SSLSocket) ((SSLSocketFactory) SSLSocketFactory.getDefault())
                .createSocket(plain, cfg.host, cfg.port, true);
            SSLParameters params = tls.getSSLParameters();
            params.setEndpointIdentificationAlgorithm("HTTPS");
            tls.setSSLParameters(params); tls.startHandshake();
            return tls;
        } catch (IOException e) { try { plain.close(); } catch (IOException ignored) {} throw e; }
    }
    private Reply socks(Socket sock, String targetHost, int targetPort, int cmd) throws IOException {
        InputStream in = sock.getInputStream(); OutputStream out = sock.getOutputStream();
        boolean auth = !cfg.username.isEmpty() || !cfg.password.isEmpty();
        out.write(auth ? new byte[]{5, 1, 2} : new byte[]{5, 1, 0}); out.flush();
        byte[] select = readN(in, 2);
        if (select[0] != 5 || select[1] != (auth ? 2 : 0)) throw new IOException("SOCKS5 auth method not accepted");
        if (select[1] == 2) {
            byte[] u = cfg.username.getBytes(StandardCharsets.UTF_8);
            byte[] p = cfg.password.getBytes(StandardCharsets.UTF_8);
            if (u.length > 255 || p.length > 255) throw new IOException("SOCKS5 credentials too long");
            out.write(1); out.write(u.length); out.write(u); out.write(p.length); out.write(p); out.flush();
            byte[] status = readN(in, 2);
            if (status[1] != 0) throw new IOException("SOCKS5 username/password rejected");
        }
        ByteArrayOutputStream request = new ByteArrayOutputStream();
        request.write(5); request.write(cmd); request.write(0);
        if (isIpv4(targetHost)) {
            request.write(1); for (String v : targetHost.split("\\.")) request.write(Integer.parseInt(v));
        } else {
            byte[] domain = targetHost.getBytes(StandardCharsets.UTF_8);
            if (domain.length > 255) throw new IOException("Target domain too long");
            request.write(3); request.write(domain.length); request.write(domain);
        }
        request.write(targetPort >>> 8); request.write(targetPort & 255); out.write(request.toByteArray()); out.flush();
        byte[] head = readN(in, 4);
        if (head[0] != 5 || head[1] != 0) throw new IOException("SOCKS5 error code " + (head[1] & 255));
        String addr; int atyp = head[3] & 255;
        if (atyp == 1) { byte[] a = readN(in, 4); addr = (a[0]&255)+"."+(a[1]&255)+"."+(a[2]&255)+"."+(a[3]&255); }
        else if (atyp == 3) { byte[] b = readN(in, 1); addr = new String(readN(in, b[0]&255), StandardCharsets.UTF_8); }
        else if (atyp == 4) { addr = InetAddress.getByAddress(readN(in, 16)).getHostAddress(); }
        else throw new IOException("Unsupported SOCKS5 response ATYP");
        byte[] pb = readN(in, 2);
        return new Reply(addr, ((pb[0] & 255)<<8) | (pb[1]&255));
    }
    private void httpConnect(Socket sock, String host, int port) throws IOException {
        String authority = host.contains(":") ? "[" + host + "]:" + port : host + ":" + port;
        String credentials = cfg.username + ":" + cfg.password;
        String auth = cfg.username.isEmpty() && cfg.password.isEmpty() ? "" :
            "Proxy-Authorization: Basic " + Base64.getEncoder().encodeToString(credentials.getBytes(StandardCharsets.UTF_8)) + "\r\n";
        String request = "CONNECT " + authority + " HTTP/1.1\r\nHost: " + authority +
            "\r\nProxy-Connection: keep-alive\r\n" + auth + "\r\n";
        sock.getOutputStream().write(request.getBytes(StandardCharsets.US_ASCII)); sock.getOutputStream().flush();
        InputStream in = sock.getInputStream();
        ByteArrayOutputStream headers = new ByteArrayOutputStream();
        int match = 0, c;
        while ((c = in.read()) != -1) {
            headers.write(c);
            match = (c == "\r\n\r\n".charAt(match)) ? match + 1 : (c == '\r' ? 1 : 0);
            if (match == 4) break;
            if (headers.size() > 16384) throw new IOException("Proxy headers too large");
        }
        if (match != 4) throw new EOFException("Incomplete proxy CONNECT reply");
        String first = headers.toString("ISO-8859-1").split("\r\n", 2)[0];
        if (!first.matches("HTTP/1\\.[01] 2[0-9][0-9]( .*|)"))
            throw new IOException("Proxy CONNECT refused: " + first);
    }
    static boolean isIpv4(String host) {
        if (host == null) return false;
        String[] octets = host.split("\\.", -1);
        if (octets.length != 4) return false;
        for (String x : octets) {
            if (x.length() < 1 || x.length() > 3) return false;
            for (char c : x.toCharArray()) if (c < '0' || c > '9') return false;
            if (Integer.parseInt(x) > 255) return false;
        }
        return true;
    }
    static byte[] readN(InputStream in, int n) throws IOException {
        byte[] buf = new byte[n]; int count = 0;
        while (count < n) {
            int r = in.read(buf, count, n - count); if (r < 0) throw new EOFException(); count += r;
        }
        return buf;
    }
    static final class Reply {
        final String host; final int port;
        Reply(String h, int p) { host = h; port = p; }
    }
    static final class UdpAssociation implements AutoCloseable {
        final Socket control; final String host; final int port;
        UdpAssociation(Socket s, String h, int p) { control = s; host = h; port = p; }
        @Override public void close() { try { control.close(); } catch (IOException ignored) {} }
    }
}
