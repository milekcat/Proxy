package com.proxyvpn.app;

import java.io.ByteArrayOutputStream;
import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.util.Locale;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;

/** DNS packets travel through the configured proxy to a verified DoH TLS endpoint. */
final class DnsOverHttps {
    private DnsOverHttps() { }
    static byte[] query(ProxyTransport proxy, byte[] request) throws IOException {
        IOException first = null;
        for (String domain : new String[]{"cloudflare-dns.com", "dns.google"}) {
            try { return request(proxy, domain, request); }
            catch (IOException e) { if (first == null) first=e; }
        }
        throw new IOException("Both DNS-over-HTTPS endpoints failed", first);
    }
    private static byte[] request(ProxyTransport proxy, String hostname, byte[] body) throws IOException {
        try (Socket through = proxy.connect(hostname,443);
             SSLSocket tls = (SSLSocket) ((SSLSocketFactory) SSLSocketFactory.getDefault()).createSocket(through,hostname,443,true)) {
            tls.setSoTimeout(12000);
            SSLParameters parameters=tls.getSSLParameters();
            parameters.setEndpointIdentificationAlgorithm("HTTPS");
            tls.setSSLParameters(parameters);tls.startHandshake();
            OutputStream out=tls.getOutputStream(); InputStream in=tls.getInputStream();
            String hdr="POST /dns-query HTTP/1.1\r\nHost: "+hostname+"\r\nAccept: application/dns-message\r\n"+
                "Content-Type: application/dns-message\r\nContent-Length: "+body.length+"\r\nConnection: close\r\n\r\n";
            out.write(hdr.getBytes(StandardCharsets.US_ASCII));out.write(body);out.flush();
            String status=line(in);
            if (!status.matches("HTTP/1\\.[01] 200( .*|)")) throw new IOException("DoH returned " + status);
            int length=-1;boolean chunked=false;
            for (;;) {
                String l=line(in);if(l.isEmpty())break;
                String low=l.toLowerCase(Locale.ROOT);
                if(low.startsWith("content-length:")) length=Integer.parseInt(l.substring(l.indexOf(':')+1).trim());
                if(low.startsWith("transfer-encoding:") && low.contains("chunked"))chunked=true;
            }
            ByteArrayOutputStream result = new ByteArrayOutputStream();
            if(chunked) {
                while(true){
                    String sizeLine=line(in).split(";",2)[0].trim();
                    int count=Integer.parseInt(sizeLine,16);
                    if(count==0)break;
                    if(result.size()+count>65535)throw new IOException("DNS payload too large");
                    result.write(ProxyTransport.readN(in,count));
                    line(in);
                }
            } else if(length>=0) {
                if(length>65535)throw new IOException("DNS payload too large");
                result.write(ProxyTransport.readN(in,length));
            } else {
                byte[] buf=new byte[4096];int n;
                while((n=in.read(buf))!=-1){result.write(buf,0,n);if(result.size()>65535)throw new IOException("DNS payload too large");}
            }
            return result.toByteArray();
        }
    }
    private static String line(InputStream in) throws IOException {
        ByteArrayOutputStream b=new ByteArrayOutputStream();int c;
        while((c=in.read())!=-1){
            if(c=='\n')break;
            if(c!='\r')b.write(c);
            if(b.size()>8192)throw new IOException("HTTP line too long");
        }
        if(c==-1)throw new EOFException();
        return b.toString("ISO-8859-1");
    }
}
