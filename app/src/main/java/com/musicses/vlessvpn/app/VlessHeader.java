package com.musicses.vlessvpn.app;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;

/**
 * Builds the VLESS binary request header.
 *
 * FIX: 不再对域名做 DNS 解析（InetAddress.getByName），
 *      域名直接以 atype=0x02 编码，避免：
 *        1. TUN 建立后 DNS 查询走隧道造成死锁
 *        2. 把域名解析成 IP 导致服务端无法按 SNI 路由
 *
 * Header format (mirrors client.js buildVlessHeader):
 *   [0]      version   = 0x00
 *   [1..16]  UUID bytes (16 bytes)
 *   [17]     addon_len = 0x00
 *   [18]     cmd       = 0x01 (TCP)
 *   [19..20] port      (big-endian uint16)
 *   [21]     atype     (1=IPv4, 2=domain, 3=IPv6)
 *   [22+]    address bytes
 */
public class VlessHeader {

    public static byte[] build(String uuid, String host, int port) {
        byte[] uid = hexToBytes(uuid.replace("-", ""));

        byte atype;
        byte[] abuf;

        if (isIPv4Literal(host)) {
            // IPv4 字面量，直接解析，不做 DNS
            atype = 0x01;
            String[] parts = host.split("\\.");
            abuf = new byte[]{
                    (byte) Integer.parseInt(parts[0]),
                    (byte) Integer.parseInt(parts[1]),
                    (byte) Integer.parseInt(parts[2]),
                    (byte) Integer.parseInt(parts[3])
            };
        } else if (host.contains(":")) {
            // IPv6 字面量（含冒号），用 InetAddress 解析字面量（不 DNS）
            try {
                // 去掉方括号（如 [::1]）
                String h = host.startsWith("[") ? host.substring(1, host.length() - 1) : host;
                atype = 0x03;
                abuf  = InetAddress.getByName(h).getAddress(); // 只解析字面量 IP，不 DNS
            } catch (UnknownHostException e) {
                // 降级为域名
                atype = 0x02;
                byte[] db = host.getBytes(StandardCharsets.UTF_8);
                abuf = new byte[1 + db.length];
                abuf[0] = (byte) db.length;
                System.arraycopy(db, 0, abuf, 1, db.length);
            }
        } else {
            // 域名，直接编码，绝对不做 DNS 解析
            atype = 0x02;
            byte[] db = host.getBytes(StandardCharsets.UTF_8);
            abuf = new byte[1 + db.length];
            abuf[0] = (byte) db.length;
            System.arraycopy(db, 0, abuf, 1, db.length);
        }

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

    /** 判断是否是 IPv4 点分十进制字面量，不做 DNS */
    private static boolean isIPv4Literal(String host) {
        String[] parts = host.split("\\.", -1);
        if (parts.length != 4) return false;
        for (String p : parts) {
            try {
                int v = Integer.parseInt(p);
                if (v < 0 || v > 255) return false;
            } catch (NumberFormatException e) {
                return false;
            }
        }
        return true;
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