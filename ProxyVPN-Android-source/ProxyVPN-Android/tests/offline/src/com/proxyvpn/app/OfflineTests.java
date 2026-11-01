package com.proxyvpn.app;

import android.net.VpnService;
import java.io.*;
import java.net.*;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Base64;
import java.util.concurrent.*;

public final class OfflineTests {
    private static void require(boolean ok, String message) {
        if (!ok) throw new AssertionError(message);
    }
    private static void eq(byte[] a, byte[] b, String message) {
        require(Arrays.equals(a, b), message + ": " + Arrays.toString(a));
    }
    public static void main(String[] args) throws Exception {
        codec();
        socks();
        socksUdp();
        http();
        System.out.println("PASS: IPv4 packet codec, SOCKS5 auth/CONNECT, SOCKS5 UDP ASSOCIATE, HTTP Basic CONNECT");
    }
    private static void codec() {
        PacketCodec.Packet request = new PacketCodec.Packet(PacketCodec.UDP,
                0x0a5b0002,0x01010101,40000,53,0,0,0, new byte[]{4,2,1});
        byte[] output = PacketCodec.udp(request,new byte[]{1,2,3});
        PacketCodec.Packet result = PacketCodec.parse(output, output.length);
        require(result != null && result.protocol == 17, "UDP parse");
        require(result.src == request.dst && result.dst == request.src, "UDP reverse IPs");
        require(result.sourcePort == 53 && result.destPort == 40000, "UDP reverse ports");
        eq(result.data, new byte[]{1,2,3}, "UDP payload");
        PacketCodec.Packet syn = new PacketCodec.Packet(PacketCodec.TCP,
                0x0a5b0002,0x01010101,49999,443,100,0,2,new byte[0]);
        byte[] reply = PacketCodec.tcp(syn,800,101,18,new byte[0]);
        PacketCodec.Packet parsed=PacketCodec.parse(reply,reply.length);
        require(parsed != null && parsed.flags == 18 && parsed.seq == 800 && parsed.ack == 101, "SYN/ACK fields");
        require(PacketCodec.dist32(0,0xffffffffL)==1L, "TCP wrap arithmetic");
        require(PacketCodec.parse(new byte[19],19)==null, "Invalid packet rejected");
    }
    private static void socks() throws Exception {
        try(ServerSocket listen = new ServerSocket(0,1,InetAddress.getByName("127.0.0.1"))) {
            ExecutorService pool = Executors.newSingleThreadExecutor();
            Future<?> server=pool.submit(()-> {
                try (Socket client=listen.accept()) {
                    client.setSoTimeout(10000);
                    InputStream in=client.getInputStream(); OutputStream out=client.getOutputStream();
                    eq(ProxyTransport.readN(in,3),new byte[]{5,1,2},"SOCKS auth greeting");
                    out.write(new byte[]{5,2});out.flush();
                    require(in.read()==1,"Username password auth version");
                    int ulen=in.read();String u=new String(ProxyTransport.readN(in,ulen), StandardCharsets.UTF_8);
                    int plen=in.read();String p=new String(ProxyTransport.readN(in,plen), StandardCharsets.UTF_8);
                    require(u.equals("user") && p.equals("secret"),"SOCKS credentials");
                    out.write(new byte[]{1,0});out.flush();
                    eq(ProxyTransport.readN(in,4),new byte[]{5,1,0,1},"SOCKS connect request");
                    eq(ProxyTransport.readN(in,4),new byte[]{(byte)93,(byte)184,(byte)216,34},"SOCKS target IPv4");
                    eq(ProxyTransport.readN(in,2),new byte[]{1,(byte)187},"SOCKS target port 443");
                    out.write(new byte[]{5,0,0,1,127,0,0,1,0,0});out.flush();
                    eq(ProxyTransport.readN(in,4),"ping".getBytes(StandardCharsets.US_ASCII),"SOCKS tunneled request");
                    out.write("pong".getBytes(StandardCharsets.US_ASCII));out.flush();
                } catch (Exception e) {throw new RuntimeException(e);}
            });
            ProxyConfig cfg=new ProxyConfig(ProxyConfig.Mode.SOCKS5,"127.0.0.1",listen.getLocalPort(),"user","secret");
            try(Socket pipe = new ProxyTransport(new VpnService(),cfg).connect("93.184.216.34",443)) {
                pipe.getOutputStream().write("ping".getBytes(StandardCharsets.US_ASCII));
                eq(ProxyTransport.readN(pipe.getInputStream(),4),"pong".getBytes(StandardCharsets.US_ASCII),"SOCKS tunneled reply");
            }
            server.get(10,TimeUnit.SECONDS);pool.shutdownNow();
        }
    }
    private static void socksUdp() throws Exception {
        try(ServerSocket listen = new ServerSocket(0,1,InetAddress.getByName("127.0.0.1"))) {
            ExecutorService pool = Executors.newSingleThreadExecutor();
            Future<?> server = pool.submit(()-> {
                try(Socket client=listen.accept()) {
                    client.setSoTimeout(10000);
                    InputStream in=client.getInputStream();OutputStream out=client.getOutputStream();
                    eq(ProxyTransport.readN(in,3),new byte[]{5,1,2},"SOCKS UDP greeting");
                    out.write(new byte[]{5,2});out.flush();
                    require(in.read()==1,"SOCKS UDP auth version");
                    int un=in.read(); ProxyTransport.readN(in,un);
                    int pn=in.read(); ProxyTransport.readN(in,pn);
                    out.write(new byte[]{1,0});out.flush();
                    eq(ProxyTransport.readN(in,4),new byte[]{5,3,0,1},"SOCKS UDP ASSOCIATE command");
                    eq(ProxyTransport.readN(in,6),new byte[]{0,0,0,0,0,0},"SOCKS UDP origin");
                    out.write(new byte[]{5,0,0,1,127,0,0,1,0x1f,(byte)0x90});out.flush();
                    while(in.read()!=-1) { }
                }catch(Exception e){throw new RuntimeException(e);}
            });
            ProxyConfig cfg=new ProxyConfig(ProxyConfig.Mode.SOCKS5,"127.0.0.1",listen.getLocalPort(),"user","secret");
            try(ProxyTransport.UdpAssociation relay=new ProxyTransport(new VpnService(),cfg).associate()) {
                require("127.0.0.1".equals(relay.host) && relay.port==8080,"UDP relay details");
            }
            server.get(10,TimeUnit.SECONDS);pool.shutdownNow();
        }
    }
    private static void http() throws Exception {
        try(ServerSocket listen = new ServerSocket(0,1,InetAddress.getByName("127.0.0.1"))) {
            ExecutorService pool=Executors.newSingleThreadExecutor();
            Future<?> server=pool.submit(()-> {
                try(Socket client=listen.accept()) {
                    client.setSoTimeout(10000);
                    BufferedReader br=new BufferedReader(new InputStreamReader(client.getInputStream(),StandardCharsets.ISO_8859_1));
                    String first=br.readLine();require("CONNECT 93.184.216.34:443 HTTP/1.1".equals(first),"HTTP CONNECT request");
                    String authorization=null,line;
                    while((line=br.readLine())!=null && !line.isEmpty()) {
                        if(line.startsWith("Proxy-Authorization: "))authorization=line.substring("Proxy-Authorization: ".length());
                    }
                    require(("Basic "+Base64.getEncoder().encodeToString("user:secret".getBytes(StandardCharsets.UTF_8))).equals(authorization),"HTTP Basic authorization");
                    OutputStream out=client.getOutputStream();InputStream in=client.getInputStream();
                    out.write("HTTP/1.1 200 Connection Established\r\n\r\n".getBytes(StandardCharsets.US_ASCII));out.flush();
                    eq(ProxyTransport.readN(in,4),"ping".getBytes(StandardCharsets.US_ASCII),"HTTP tunneled request");
                    out.write("pong".getBytes(StandardCharsets.US_ASCII));out.flush();
                }catch(Exception e){throw new RuntimeException(e);}
            });
            ProxyConfig cfg=new ProxyConfig(ProxyConfig.Mode.HTTP,"127.0.0.1",listen.getLocalPort(),"user","secret");
            try(Socket pipe=new ProxyTransport(new VpnService(),cfg).connect("93.184.216.34",443)) {
                pipe.getOutputStream().write("ping".getBytes(StandardCharsets.US_ASCII));
                eq(ProxyTransport.readN(pipe.getInputStream(),4),"pong".getBytes(StandardCharsets.US_ASCII),"HTTP tunneled reply");
            }
            server.get(10,TimeUnit.SECONDS);pool.shutdownNow();
        }
    }
}
