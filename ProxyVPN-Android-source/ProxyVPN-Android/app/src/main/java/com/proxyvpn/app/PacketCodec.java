package com.proxyvpn.app;

import java.util.Arrays;
import java.security.SecureRandom;

/** IPv4 transport packet codec. This MVP deliberately drops IPv6 and fragmented packets. */
final class PacketCodec {
    static final int TCP = 6, UDP = 17;
    private static final SecureRandom RNG = new SecureRandom();
    private PacketCodec() { }
    static int u8(byte[] a, int p) { return a[p] & 255; }
    static int u16(byte[] a, int p) { return (u8(a,p)<<8) | u8(a,p+1); }
    static long u32(byte[] a, int p) { return (((long)u16(a,p))<<16) | u16(a,p+2); }
    static int i32(byte[] a, int p) { return (int)u32(a,p); }
    static void w16(byte[] a, int p, int n) { a[p]=(byte)(n>>>8); a[p+1]=(byte)n; }
    static void w32(byte[] a, int p, long n) { w16(a,p,(int)(n>>>16)); w16(a,p+2,(int)n); }
    static long add32(long a, long b) { return (a+b) & 0xffffffffL; }
    static long dist32(long a, long b) { return (a-b) & 0xffffffffL; }
    static String addr(int n) { return ((n>>>24)&255)+"."+((n>>>16)&255)+"."+((n>>>8)&255)+"."+(n&255); }
    static int random16() { return RNG.nextInt(65536); }
    static long random32() { return RNG.nextInt() & 0xffffffffL; }

    static Packet parse(byte[] buf, int n) {
        if (n < 20 || (u8(buf,0)>>>4)!=4) return null;
        int ihl = (u8(buf,0)&15)*4; if (ihl<20 || n<ihl) return null;
        int total = u16(buf,2); if (total<ihl || total>n) return null;
        if ((u16(buf,6)&0x3fff)!=0) return null; // no IPv4 fragmentation in MVP
        int proto = u8(buf,9), src=i32(buf,12), dst=i32(buf,16);
        if (proto==TCP) {
            if (total-ihl<20) return null;
            int thl=(u8(buf,ihl+12)>>>4)*4;
            if (thl<20 || ihl+thl>total) return null;
            return new Packet(proto,src,dst,u16(buf,ihl),u16(buf,ihl+2),
                u32(buf,ihl+4),u32(buf,ihl+8),u8(buf,ihl+13),
                Arrays.copyOfRange(buf,ihl+thl,total));
        } else if (proto==UDP) {
            if (total-ihl<8) return null;
            int ulen=u16(buf,ihl+4);
            if (ulen<8 || ihl+ulen>total) return null;
            return new Packet(proto,src,dst,u16(buf,ihl),u16(buf,ihl+2),0,0,0,
                Arrays.copyOfRange(buf,ihl+8,ihl+ulen));
        }
        return null;
    }
    static final class Packet {
        final int protocol, src, dst, sourcePort, destPort, flags;
        final long seq, ack;
        final byte[] data;
        Packet(int proto,int s,int d,int sp,int dp,long sq,long ak,int f,byte[] dat) {
            protocol=proto;src=s;dst=d;sourcePort=sp;destPort=dp;seq=sq;ack=ak;flags=f;data=dat;
        }
        String key() {return src+":"+sourcePort+"/"+dst+":"+destPort;}
    }
    static byte[] tcp(Packet request, long seq, long ack, int flags, byte[] payload) {
        int ipHeader=20,tcpHeader=20;
        boolean syn=(flags&2)!=0;
        if (syn) tcpHeader+=4; // advertise MSS 1360
        int len=ipHeader+tcpHeader+payload.length;
        byte[] p=new byte[len]; ip(p,len,request.dst,request.src,TCP);
        w16(p,20,request.destPort);w16(p,22,request.sourcePort);
        w32(p,24,seq);w32(p,28,ack);
        p[32]=(byte)((tcpHeader/4)<<4);p[33]=(byte)flags;
        w16(p,34,65535);
        if (syn) {p[40]=2;p[41]=4;w16(p,42,1360);}
        System.arraycopy(payload,0,p,20+tcpHeader,payload.length);
        w16(p,36,transportChecksum(p,request.dst,request.src,TCP,20,len-20));
        return p;
    }
    static byte[] udp(Packet request, byte[] payload) {
        int len=28+payload.length;byte[] p=new byte[len];
        ip(p,len,request.dst,request.src,UDP);
        w16(p,20,request.destPort); w16(p,22,request.sourcePort);
        w16(p,24,8+payload.length);
        System.arraycopy(payload,0,p,28,payload.length);
        int sum=transportChecksum(p,request.dst,request.src,UDP,20,len-20);
        w16(p,26,sum==0 ? 0xffff : sum);
        return p;
    }
    private static void ip(byte[] p,int total,int src,int dst,int protocol) {
        p[0]=0x45;p[1]=0;w16(p,2,total);w16(p,4,random16());
        w16(p,6,0x4000);p[8]=64;p[9]=(byte)protocol;
        w32(p,12,src);w32(p,16,dst);
        w16(p,10,checksum(p,0,20,0));
    }
    private static int checksum(byte[] p,int offset,int count,long init) {
        long sum=init;
        for(int i=offset;i<offset+count-1;i+=2) sum+=u16(p,i);
        if((count&1)!=0) sum+=(u8(p,offset+count-1)<<8);
        while((sum>>>16)!=0)sum=(sum&65535)+(sum>>>16);
        return (int)(~sum)&65535;
    }
    private static int transportChecksum(byte[] p,int s,int d,int proto,int off,int count) {
        long pseudo=((s>>>16)&65535)+(s&65535)+((d>>>16)&65535)+(d&65535)+proto+count;
        return checksum(p,off,count,pseudo);
    }
}
