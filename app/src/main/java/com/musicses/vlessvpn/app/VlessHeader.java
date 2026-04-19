package com.musicses.vlessvpn.app;

import java.net.Inet4Address;
import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.nio.ByteBuffer;

/**
 * Builds the VLESS binary request header.
 *
 * Mirrors the logic in client.js → buildVlessHeader():
 *
 * Fixed 22-byte prefix:
 *   [0]      version   = 0x00
 *   [1..16]  UUID bytes (16 bytes)
 *   [17]     addon_len = 0x00
 *   [18]     cmd       = 0x01 (TCP)
 *   [19..20] port      (big-endian uint16)
 *   [21]     atype     (1=IPv4, 2=domain, 3=IPv6)
 *
 * Then the address bytes:
 *   atype==1 → 4 bytes IPv4
 *   atype==2 → 1 byte length + utf8 domain
 *   atype==3 → 16 bytes IPv6
 */
public class VlessHeader {

    public static byte[] build(String uuid, String host, int port) {
        byte[] uid = hexToBytes(uuid.replace("-", ""));

        byte atype;
        byte[] abuf;

        try {
            InetAddress addr = InetAddress.getByName(host);
            if (addr instanceof Inet4Address) {
                atype = 0x01;
                abuf  = addr.getAddress(); // 4 bytes
            } else if (addr instanceof Inet6Address) {
                atype = 0x03;
                abuf  = addr.getAddress(); // 16 bytes
            } else {
                // domain fallback
                atype = 0x02;
                byte[] db = host.getBytes();
                abuf = new byte[1 + db.length];
                abuf[0] = (byte) db.length;
                System.arraycopy(db, 0, abuf, 1, db.length);
            }
        } catch (UnknownHostException e) {
            // treat as domain name
            atype = 0x02;
            byte[] db = host.getBytes();
            abuf = new byte[1 + db.length];
            abuf[0] = (byte) db.length;
            System.arraycopy(db, 0, abuf, 1, db.length);
        }

        // Build fixed 22-byte header
        ByteBuffer buf = ByteBuffer.allocate(22 + abuf.length);
        buf.put((byte) 0x00);           // version
        buf.put(uid);                   // 16 bytes UUID
        buf.put((byte) 0x00);           // addon length
        buf.put((byte) 0x01);           // cmd = TCP
        buf.putShort((short) port);     // port big-endian
        buf.put(atype);                 // address type
        buf.put(abuf);                  // address

        return buf.array();
    }

    private static byte[] hexToBytes(String hex) {
        int len = hex.length();
        byte[] out = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            out[i / 2] = (byte) ((Character.digit(hex.charAt(i), 16) << 4)
                    + Character.digit(hex.charAt(i + 1), 16));
        }
        return out;
    }
}
