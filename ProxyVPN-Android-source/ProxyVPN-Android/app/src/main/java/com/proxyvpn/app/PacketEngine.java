package com.proxyvpn.app;

import android.net.VpnService;
import android.os.ParcelFileDescriptor;
import android.util.Log;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.SocketException;
import java.util.ArrayDeque;
import java.util.Arrays;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.Semaphore;

/**
 * Educational, native-Java IPv4 TCP/UDP -> authenticated proxy VPN gateway.
 * Does not claim production-grade TCP reliability: see README for limits.
 */
final class PacketEngine implements AutoCloseable {
    private final VpnService vpn;
    private final ParcelFileDescriptor tun;
    private final ProxyConfig cfg;
    private final ProxyTransport proxy;
    private final FileInputStream input;
    private final FileOutputStream output;
    private final Object outputLock = new Object();
    private final ConcurrentHashMap<String,TcpFlow> tcp = new ConcurrentHashMap<>();
    private final ConcurrentHashMap<String,UdpFlow> udp = new ConcurrentHashMap<>();
    private final ExecutorService workers = Executors.newCachedThreadPool();
    private final ScheduledExecutorService scheduler = Executors.newSingleThreadScheduledExecutor();
    private final AtomicBoolean live = new AtomicBoolean(true);
    private final Semaphore dnsSlots = new Semaphore(24);

    PacketEngine(VpnService vpn, ParcelFileDescriptor fd, ProxyConfig cfg) {
        this.vpn=vpn; this.tun=fd; this.cfg=cfg; proxy=new ProxyTransport(vpn,cfg);
        input=new FileInputStream(fd.getFileDescriptor()); output=new FileOutputStream(fd.getFileDescriptor());
    }
    void start() {
        workers.execute(this::loop);
        scheduler.scheduleAtFixedRate(this::tick, 500, 500, TimeUnit.MILLISECONDS);
    }
    private void loop() {
        byte[] buffer=new byte[65535];
        while(live.get()) {
            try {
                int n=input.read(buffer);
                if(n<0)break;
                PacketCodec.Packet p=PacketCodec.parse(buffer,n);
                if(p==null)continue; // includes IPv6; deliberately fail closed
                if(p.protocol==PacketCodec.TCP) onTcp(p);
                else if(p.protocol==PacketCodec.UDP) onUdp(p);
            } catch(IOException e) {
                if(live.get())Log.w("ProxyVPN","VPN interface read failed");
                break;
            } catch(RuntimeException e) { Log.w("ProxyVPN","Rejected malformed packet"); }
        }
        close();
    }
    private void send(byte[] p) {
        if(!live.get())return;
        try { synchronized(outputLock) { output.write(p); } }
        catch(IOException ignored) { }
    }
    private void onTcp(PacketCodec.Packet p) {
        String key=p.key(); TcpFlow f=tcp.get(key);
        if(f==null) {
            if((p.flags&0x02)==0 || tcp.size()>=256)return;
            TcpFlow candidate=new TcpFlow(p);
            TcpFlow previous=tcp.putIfAbsent(key,candidate);
            if(previous==null) { candidate.open(); return; }
            f=previous;
        }
        f.onPacket(p);
    }
    private void onUdp(PacketCodec.Packet p) {
        if(p.destPort==53) {
            // DoH goes only through the upstream proxy; no direct DNS traffic.
            if (!dnsSlots.tryAcquire()) return;
            workers.execute(()->{
                try { byte[] answer=DnsOverHttps.query(proxy,p.data); if(live.get())send(PacketCodec.udp(p,answer)); }
                catch(Exception e){Log.w("ProxyVPN","DNS via proxy failed");}
                finally { dnsSlots.release(); }
            });
        } else if(cfg.mode==ProxyConfig.Mode.SOCKS5) {
            String key=p.key();UdpFlow f=udp.get(key);
            if(f==null) {
                if(udp.size()>=128)return;
                UdpFlow candidate=new UdpFlow(p);
                UdpFlow previous=udp.putIfAbsent(key,candidate);
                f=(previous!=null)?previous:candidate;
                if(previous==null)f.open();
            }
            f.offer(p);
        }
        // An HTTP(S) CONNECT proxy cannot forward arbitrary UDP. Drop it rather
        // than leak it via a direct socket. Most browsers retry QUIC over TCP.
    }
    private void tick() {
        if(!live.get())return;
        long now=System.currentTimeMillis();
        for(TcpFlow f:tcp.values()) {
            if(now-f.lastSeen>120000) f.close(); else f.retransmit(now);
        }
        for(UdpFlow f:udp.values())if(now-f.lastSeen>90000)f.close();
    }
    @Override public void close() {
        if(!live.getAndSet(false))return;
        scheduler.shutdownNow();
        try{tun.close();}catch(IOException ignored){}
        for(TcpFlow f:tcp.values())f.close();
        for(UdpFlow f:udp.values())f.close();
        tcp.clear();udp.clear();workers.shutdownNow();
    }
    private final class TcpFlow {
        private static final int SYN=2, ACK=16, PSH=8, FIN=1, RST=4;
        final PacketCodec.Packet origin;
        final String key;
        final long initialRemoteSeq;
        final long initialLocalSeq=PacketCodec.random32();
        final ArrayDeque<byte[]> awaitingWrite=new ArrayDeque<>();
        final ArrayDeque<Sent> sent=new ArrayDeque<>();
        volatile long lastSeen=System.currentTimeMillis();
        long nextRemote, nextLocal;
        int queuedBytes=0;
        boolean established=false,handshakeAcked=false,remoteFin=false,localFin=false,dead=false;
        long synAckLastSent=0; int synAckRetries=0;
        Socket upstream;
        TcpFlow(PacketCodec.Packet p) {
            origin=p;key=p.key();initialRemoteSeq=p.seq;
            nextRemote=PacketCodec.add32(p.seq,1);
            nextLocal=PacketCodec.add32(initialLocalSeq,1);
        }
        void open() {
            workers.execute(()->{
                try {
                    Socket s=proxy.connect(PacketCodec.addr(origin.dst),origin.destPort);
                    synchronized(this) {
                        if(dead) {s.close();return;}
                        upstream=s;established=true;
                        sendSynAck();
                    }
                    workers.execute(this::writePump);
                    readPump();
                } catch(Exception e) {
                    synchronized(this) {
                        if(!dead)send(PacketCodec.tcp(origin,0,nextRemote,RST|ACK,new byte[0]));
                    }
                } finally {close();}
            });
        }
        synchronized void onPacket(PacketCodec.Packet p) {
            if(dead)return;
            lastSeen=System.currentTimeMillis();
            if((p.flags&RST)!=0){close();return;}
            if(!established)return;
            if((p.flags&SYN)!=0) {sendSynAck();return;}
            if((p.flags&ACK)!=0 && p.ack==PacketCodec.add32(initialLocalSeq,1)) {
                handshakeAcked=true;notifyAll();
            }
            // cumulative ACK; serial arithmetic deals with 32-bit wrapping
            if((p.flags&ACK)!=0) {
                while(!sent.isEmpty() && PacketCodec.dist32(p.ack,sent.peek().end)<0x80000000L){sent.poll();notifyAll();}
            }
            byte[] data=p.data;
            long overlap=PacketCodec.dist32(nextRemote,p.seq);
            if(data.length>0) {
                if(overlap>0x80000000L) {sendAck();return;} // future segment: await retransmission
                int skip=(int)Math.min(overlap,data.length);
                int len=data.length-skip;
                if(len>0) {
                    if(queuedBytes+len>1024*1024){close();return;} // avoid unbounded memory
                    byte[] accepted=Arrays.copyOfRange(data,skip,data.length);
                    awaitingWrite.add(accepted); queuedBytes+=len;
                    nextRemote=PacketCodec.add32(nextRemote,len);notifyAll();
                }
                sendAck();
            }
            long finSeq=PacketCodec.add32(p.seq,p.data.length);
            if((p.flags&FIN)!=0 && !remoteFin && finSeq==nextRemote) {
                remoteFin=true;nextRemote=PacketCodec.add32(nextRemote,1);
                sendAck();notifyAll();
            }
            if(localFin && remoteFin && sent.isEmpty())close();
        }
        private synchronized void sendSynAck() {
            if(!dead){
                send(PacketCodec.tcp(origin,initialLocalSeq,nextRemote,SYN|ACK,new byte[0]));
                synAckLastSent=System.currentTimeMillis();
            }
        }
        private synchronized void sendAck(){if(!dead)send(PacketCodec.tcp(origin,nextLocal,nextRemote,ACK,new byte[0]));}
        void writePump() {
            try {
                OutputStream out=upstream.getOutputStream();
                while(live.get()) {
                    byte[] chunk;
                    synchronized(this) {
                        while(!dead && awaitingWrite.isEmpty() && !remoteFin)wait(1000);
                        if(dead)return;
                        chunk=awaitingWrite.poll();
                        if(chunk!=null)queuedBytes-=chunk.length;
                        else if(remoteFin){upstream.shutdownOutput();return;}
                    }
                    if(chunk!=null){out.write(chunk);out.flush();}
                }
            } catch(Exception ignored){close();}
        }
        void readPump(){
            try {
                synchronized(this) {
                    while(!dead && !handshakeAcked && live.get()) wait(500);
                    if(dead || !live.get())return;
                }
                byte[] buffer=new byte[1300];InputStream in=upstream.getInputStream();int n;
                while(live.get() && (n=in.read(buffer))!=-1) {
                    synchronized(this){
                        while(!dead && outstanding()>65000)wait(1000);
                        if(dead)return;
                        int i=0;
                        while(i<n){
                            int size=Math.min(1300,n-i);
                            byte[] data=Arrays.copyOfRange(buffer,i,i+size);
                            long start=nextLocal;
                            nextLocal=PacketCodec.add32(nextLocal,size);
                            sent.add(new Sent(start,nextLocal,PSH|ACK,data));
                            send(PacketCodec.tcp(origin,start,nextRemote,PSH|ACK,data));
                            i+=size;
                        }
                    }
                }
                synchronized(this){
                    if(!dead){
                        long start=nextLocal;nextLocal=PacketCodec.add32(nextLocal,1);
                        sent.add(new Sent(start,nextLocal,FIN|ACK,new byte[0]));
                        send(PacketCodec.tcp(origin,start,nextRemote,FIN|ACK,new byte[0]));localFin=true;
                    }
                }
                // Wait briefly for a graceful close, while retransmits continue.
                long until=System.currentTimeMillis()+15000;
                while(live.get() && System.currentTimeMillis()<until){
                    synchronized(this){if(dead || (remoteFin && sent.isEmpty()))return;}
                    Thread.sleep(200);
                }
            }catch(Exception ignored){}finally{close();}
        }
        private long outstanding(){
            long bytes=0;for(Sent t:sent)bytes+=PacketCodec.dist32(t.end,t.start);
            return bytes;
        }
        synchronized void retransmit(long now) {
            if(dead || !established)return;
            if (!handshakeAcked && now-synAckLastSent>=1500) {
                if (synAckRetries++>=6) {close();return;}
                sendSynAck();
            }
            int n=0;
            for(Sent s:sent){
                if(now-s.lastSent>=1500 && n++<8){
                    if(s.retries++>6){close();return;}
                    send(PacketCodec.tcp(origin,s.start,nextRemote,s.flags,s.data));s.lastSent=now;
                }
            }
        }
        synchronized void close(){
            if(dead)return;dead=true;notifyAll();tcp.remove(key,this);
            if(upstream!=null)try{upstream.close();}catch(IOException ignored){}
        }
        final class Sent {
            final long start,end;final int flags;final byte[] data;
            long lastSent=System.currentTimeMillis();int retries=0;
            Sent(long s,long e,int f,byte[] d){start=s;end=e;flags=f;data=d;}
        }
    }
    private final class UdpFlow {
        final PacketCodec.Packet origin;
        final String key;
        final ArrayDeque<byte[]> pending=new ArrayDeque<>();
        volatile long lastSeen=System.currentTimeMillis();
        volatile boolean dead=false;
        DatagramSocket sock;ProxyTransport.UdpAssociation assoc;
        UdpFlow(PacketCodec.Packet p){origin=p;key=p.key();}
        synchronized void offer(PacketCodec.Packet p){
            if(dead)return;
            lastSeen=System.currentTimeMillis();
            if(pending.size()>128)return;
            pending.add(p.data);notifyAll();
        }
        void open(){
            workers.execute(()->{
                try {
                    ProxyTransport.UdpAssociation a=proxy.associate();
                    DatagramSocket d=new DatagramSocket();
                    if(!vpn.protect(d))throw new IOException("Cannot protect UDP proxy socket");
                    d.connect(new InetSocketAddress(a.host,a.port));
                    d.setSoTimeout(2000);
                    synchronized(this){if(dead){d.close();a.close();return;}assoc=a;sock=d;}
                    workers.execute(this::sendPump);recvPump();
                }catch(Exception ignored){}finally{close();}
            });
        }
        void sendPump(){
            try{
                while(live.get()){
                    byte[] payload;
                    synchronized(this){
                        while(!dead && pending.isEmpty())wait(1000);
                        if(dead)return;
                        payload=pending.poll();
                    }
                    if(payload!=null){
                        // RFC 1928 UDP REQUEST: RSV(2), FRAG(1), ATYP(1), DST(4), PORT(2), DATA
                        byte[] b=new byte[10+payload.length];b[3]=1;
                        PacketCodec.w32(b,4,origin.dst);PacketCodec.w16(b,8,origin.destPort);
                        System.arraycopy(payload,0,b,10,payload.length);
                        sock.send(new DatagramPacket(b,b.length));
                    }
                }
            }catch(Exception ignored){close();}
        }
        void recvPump(){
            try{
                byte[] b=new byte[65535];
                while(live.get()&&!dead){
                    try{
                        DatagramPacket d=new DatagramPacket(b,b.length);sock.receive(d);
                        int n=d.getLength();if(n<10 || b[2]!=0)continue;
                        int off;
                        if(b[3]==1)off=10;
                        else if(b[3]==3){if(n<5)continue;off=5+(b[4]&255)+2;}
                        else if(b[3]==4)off=22;
                        else continue;
                        if(off>n)continue;
                        lastSeen=System.currentTimeMillis();
                        send(PacketCodec.udp(origin,Arrays.copyOfRange(b,off,n)));
                    }catch(java.net.SocketTimeoutException ignored){}
                }
            }catch(Exception ignored){}finally{close();}
        }
        synchronized void close(){
            if(dead)return;dead=true;notifyAll();udp.remove(key,this);
            if(sock!=null)sock.close();if(assoc!=null)assoc.close();
        }
    }
}
