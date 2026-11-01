package android.net;

import java.net.Socket;
import java.net.DatagramSocket;

/** Test-only stub. This file is NOT included in the Android application. */
public class VpnService {
    public boolean protect(Socket socket) { return true; }
    public boolean protect(DatagramSocket socket) { return true; }
}
