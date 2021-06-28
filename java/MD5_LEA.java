package org.inurl.example;

import com.google.common.base.Strings;
import org.apache.commons.codec.binary.Hex;
import org.apache.commons.codec.digest.DigestUtils;

/**
 * @author raylax
 */
public class MD5_LEA {

    private static final int VA = 0x67452301;
    private static final int VB = 0xefcdab89;
    private static final int VC = 0x98badcfe;
    private static final int VD = 0x10325476;
    private static final int[] SV = {
            0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee, 0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
            0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be, 0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
            0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa, 0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
            0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed, 0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
            0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c, 0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
            0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05, 0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
            0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039, 0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
            0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1, 0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391,
    };

    private static final int[][] SS = {
            { 0x07, 0x0c, 0x11, 0x16 },
            { 0x05, 0x09, 0x0e, 0x14 },
            { 0x04, 0x0b, 0x10, 0x17 },
            { 0x06, 0x0a, 0x0f, 0x15 },
    };


    public static void main(String[] args) throws Exception {
        String key = "meme";
        String md5 = DigestUtils.md5Hex(key.getBytes());
        reverse(key,9, "admin", md5, "joychou");
    }

    private static void reverse(String secret, int len, String ap, String sm, String text) throws Exception {
        System.out.printf("     [MD5] => 0x%s%n", sm);
        final byte[] textBytes = text.getBytes();
        String test = Hex.encodeHexString(padding((Strings.repeat("a", len) + ap).getBytes())) + Hex.encodeHexString(textBytes);
        System.out.printf("填充后的数据 => 0x%s%n", test);
        System.out.printf("填充后的摘要 => 0x%s%n", Hex.encodeHexString(calc(textBytes, true, reverseABCD(sm))));
        final String data = test.substring(len * 2);
        System.out.printf("要填充的数据 => 0x%s%n", data);
        System.out.printf("编码后的数据 => %s%n", escape(Hex.decodeHex(data)));
        if (secret != null) {
            test = Hex.encodeHexString(padding(secret.getBytes())) + Hex.encodeHexString(textBytes);
            System.out.printf("   [CHECK] => %s%n", Hex.encodeHexString(calc(Hex.decodeHex(test))));
        }
    }

    private static String escape(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            if (isAlpha(b)) {
                sb.append((char) b);
            } else {
                sb.append(String.format("%%%02X", b));
            }
        }
        return sb.toString();
    }

    private static int[] reverseABCD(String hex) throws Exception {
        final byte[] bytes = Hex.decodeHex(hex);
        int[] abcd = new int[4];
        for (int i = 0; i < abcd.length; i++) {
            int offset = i * 4;
            abcd[i] = bytes[offset] & 0xff
                    | (bytes[offset + 1] & 0xff) << 8
                    | (bytes[offset + 2] & 0xff) << 16
                    | (bytes[offset + 3] & 0xff) << 24;
        }
        return abcd;
    }

    private static byte[] padding(byte[] data) {
        return padding(data, false);
    }
    private static byte[] padding(byte[] data, boolean b) {
        final int len = data.length;
        int rest = 64 - (len % 64);
        final int newLen = len + rest;
        final byte[] bytes = new byte[newLen];
        System.arraycopy(data, 0, bytes, 0, len);
       
        bytes[len] = (byte) 0x80;
       
        int bits = len * 8;
        if (b) {
            bits += 512;
        }
        final int lenOffset = newLen - 8;
        for (int i = lenOffset; i < lenOffset + 4; i++) {
            bytes[i] = (byte) ((bits >> (i * 8)) & 0xff);
        }
        return bytes;
    }

    private static byte[] calc(byte[] data) {
        return calc(data, false, null);
    }

    private static byte[] calc(byte[] data, boolean db, int[] result) {
        data = padding(data, db);
        if (result == null) {
            result = new int[]{VA, VB, VC, VD};
        }
        int groups = data.length / 64;
        for (int i = 0; i < groups; i++) {
            int offset = i * 64;
            int[] xn = new int[16];
            for (int j = 0; j < xn.length; j++) {
                int n = j * 4;
                xn[j] = (data[offset + n] & 0xff)
                        | (data[offset + n + 1] & 0xff) << 8
                        | (data[offset + n + 2] & 0xff) << 16
                        | (data[offset + n + 3] & 0xff) << 24;
            }
            int a = result[0], b = result[1], c = result[2], d = result[3];

            a = FF(a, b, c, d, xn[0], SS[0][0], SV[0]);
            d = FF(d, a, b, c, xn[1], SS[0][1], SV[1]);
            c = FF(c, d, a, b, xn[2], SS[0][2], SV[2]);
            b = FF(b, c, d, a, xn[3], SS[0][3], SV[3]);
            a = FF(a, b, c, d, xn[4], SS[0][0], SV[4]);
            d = FF(d, a, b, c, xn[5], SS[0][1], SV[5]);
            c = FF(c, d, a, b, xn[6], SS[0][2], SV[6]);
            b = FF(b, c, d, a, xn[7], SS[0][3], SV[7]);
            a = FF(a, b, c, d, xn[8], SS[0][0], SV[8]);
            d = FF(d, a, b, c, xn[9], SS[0][1], SV[9]);
            c = FF(c, d, a, b, xn[10], SS[0][2], SV[10]);
            b = FF(b, c, d, a, xn[11], SS[0][3], SV[11]);
            a = FF(a, b, c, d, xn[12], SS[0][0], SV[12]);
            d = FF(d, a, b, c, xn[13], SS[0][1], SV[13]);
            c = FF(c, d, a, b, xn[14], SS[0][2], SV[14]);
            b = FF(b, c, d, a, xn[15], SS[0][3], SV[15]);

            a = GG(a, b, c, d, xn[1], SS[1][0], SV[16]);
            d = GG(d, a, b, c, xn[6], SS[1][1], SV[17]);
            c = GG(c, d, a, b, xn[11], SS[1][2], SV[18]);
            b = GG(b, c, d, a, xn[0], SS[1][3], SV[19]);
            a = GG(a, b, c, d, xn[5], SS[1][0], SV[20]);
            d = GG(d, a, b, c, xn[10], SS[1][1], SV[21]);
            c = GG(c, d, a, b, xn[15], SS[1][2], SV[22]);
            b = GG(b, c, d, a, xn[4], SS[1][3], SV[23]);
            a = GG(a, b, c, d, xn[9], SS[1][0], SV[24]);
            d = GG(d, a, b, c, xn[14], SS[1][1], SV[25]);
            c = GG(c, d, a, b, xn[3], SS[1][2], SV[26]);
            b = GG(b, c, d, a, xn[8], SS[1][3], SV[27]);
            a = GG(a, b, c, d, xn[13], SS[1][0], SV[28]);
            d = GG(d, a, b, c, xn[2], SS[1][1], SV[29]);
            c = GG(c, d, a, b, xn[7], SS[1][2], SV[30]);
            b = GG(b, c, d, a, xn[12], SS[1][3], SV[31]);

            a = HH(a, b, c, d, xn[5], SS[2][0], SV[32]);
            d = HH(d, a, b, c, xn[8], SS[2][1], SV[33]);
            c = HH(c, d, a, b, xn[11], SS[2][2], SV[34]);
            b = HH(b, c, d, a, xn[14], SS[2][3], SV[35]);
            a = HH(a, b, c, d, xn[1], SS[2][0], SV[36]);
            d = HH(d, a, b, c, xn[4], SS[2][1], SV[37]);
            c = HH(c, d, a, b, xn[7], SS[2][2], SV[38]);
            b = HH(b, c, d, a, xn[10], SS[2][3], SV[39]);
            a = HH(a, b, c, d, xn[13], SS[2][0], SV[40]);
            d = HH(d, a, b, c, xn[0], SS[2][1], SV[41]);
            c = HH(c, d, a, b, xn[3], SS[2][2], SV[42]);
            b = HH(b, c, d, a, xn[6], SS[2][3], SV[43]);
            a = HH(a, b, c, d, xn[9], SS[2][0], SV[44]);
            d = HH(d, a, b, c, xn[12], SS[2][1], SV[45]);
            c = HH(c, d, a, b, xn[15], SS[2][2], SV[46]);
            b = HH(b, c, d, a, xn[2], SS[2][3], SV[47]);

            a = II(a, b, c, d, xn[0], SS[3][0], SV[48]);
            d = II(d, a, b, c, xn[7], SS[3][1], SV[49]);
            c = II(c, d, a, b, xn[14], SS[3][2], SV[50]);
            b = II(b, c, d, a, xn[5], SS[3][3], SV[51]);
            a = II(a, b, c, d, xn[12], SS[3][0], SV[52]);
            d = II(d, a, b, c, xn[3], SS[3][1], SV[53]);
            c = II(c, d, a, b, xn[10], SS[3][2], SV[54]);
            b = II(b, c, d, a, xn[1], SS[3][3], SV[55]);
            a = II(a, b, c, d, xn[8], SS[3][0], SV[56]);
            d = II(d, a, b, c, xn[15], SS[3][1], SV[57]);
            c = II(c, d, a, b, xn[6], SS[3][2], SV[58]);
            b = II(b, c, d, a, xn[13], SS[3][3], SV[59]);
            a = II(a, b, c, d, xn[4], SS[3][0], SV[60]);
            d = II(d, a, b, c, xn[11], SS[3][1], SV[61]);
            c = II(c, d, a, b, xn[2], SS[3][2], SV[62]);
            b = II(b, c, d, a, xn[9], SS[3][3], SV[63]);

            result[0] += a;
            result[1] += b;
            result[2] += c;
            result[3] += d;

        }

        byte[] bytes = new byte[16];
        for (int i = 0; i < bytes.length; i += 4) {
            int r = result[i / 4];
            bytes[i] = (byte) (r & 0xff);
            bytes[i + 1] = (byte) (r >> 8 & 0xff);
            bytes[i + 2] = (byte) (r >> 16 & 0xff);
            bytes[i + 3] = (byte) (r >> 24 & 0xff);
        }
        return bytes;
    }

    private static int F(int x, int y, int z) {
        return (x & y) | ((~x) & z);
    }

    private static int G(int x, int y, int z) {
        return (x & z) | (y & (~z));
    }

    private static int H(int x, int y, int z) {
        return x ^ y ^ z;
    }

    private static int I(int x, int y, int z) {
        return y ^ (x | (~z));
    }

    private static int FF(int a, int b, int c, int d, int x, int s, int t) {
        return NN(F(b, c, d), a, b, x, s, t);
    }

    private static int GG(int a, int b, int c, int d, int x, int s, int t) {
        return NN(G(b, c, d), a, b, x, s, t);
    }

    private static int HH(int a, int b, int c, int d, int x, int s, int t) {
        return NN(H(b, c, d), a, b, x, s, t);
    }

    private static int II(int a, int b, int c, int d, int x, int s, int t) {
        return NN(I(b, c, d), a, b, x, s, t);
    }

    private static int NN(int f, int a, int b, int x, int s, int t) {
        a = a + f + x + t;
        a = (a << s) | (a >>> (32 - s));
        return a + b;
    }

    private static boolean isAlpha(byte b) {
        return (b >= '0' && b <= '9') || (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z');
    }

}
