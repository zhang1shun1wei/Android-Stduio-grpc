package com.mi.car.jsse.easysec.crypto.digests;

import com.mi.car.jsse.easysec.crypto.Digest;
import com.mi.car.jsse.easysec.crypto.signers.PSSSigner;
import com.mi.car.jsse.easysec.math.ec.Tnaf;
import com.mi.car.jsse.easysec.pqc.crypto.rainbow.util.GF2Field;

public abstract class HarakaBase implements Digest {
    protected static final int DIGEST_SIZE = 32;
    private static final byte[][] S = {new byte[]{99, 124, 119, 123, -14, 107, 111, -59, 48, 1, 103, 43, -2, -41, -85, 118}, new byte[]{-54, -126, -55, 125, -6, 89, 71, -16, -83, -44, -94, -81, -100, -92, 114, -64}, new byte[]{-73, -3, -109, 38, 54, 63, -9, -52, 52, -91, -27, -15, 113, -40, 49, 21}, new byte[]{4, -57, 35, -61, 24, -106, 5, -102, 7, 18, Byte.MIN_VALUE, -30, -21, 39, -78, 117}, new byte[]{9, -125, 44, 26, 27, 110, 90, -96, 82, 59, -42, -77, 41, -29, 47, -124}, new byte[]{83, -47, 0, -19, 32, -4, -79, 91, 106, -53, -66, 57, 74, 76, 88, -49}, new byte[]{-48, -17, -86, -5, 67, 77, 51, -123, 69, -7, 2, Byte.MAX_VALUE, 80, 60, -97, -88}, new byte[]{81, -93, 64, -113, -110, -99, 56, -11, PSSSigner.TRAILER_IMPLICIT, -74, -38, 33, Tnaf.POW_2_WIDTH, -1, -13, -46}, new byte[]{-51, 12, 19, -20, 95, -105, 68, 23, -60, -89, 126, 61, 100, 93, 25, 115}, new byte[]{96, -127, 79, -36, 34, 42, -112, -120, 70, -18, -72, 20, -34, 94, 11, -37}, new byte[]{-32, 50, 58, 10, 73, 6, 36, 92, -62, -45, -84, 98, -111, -107, -28, 121}, new byte[]{-25, -56, 55, 109, -115, -43, 78, -87, 108, 86, -12, -22, 101, 122, -82, 8}, new byte[]{-70, 120, 37, 46, 28, -90, -76, -58, -24, -35, 116, 31, 75, -67, -117, -118}, new byte[]{112, 62, -75, 102, 72, 3, -10, 14, 97, 53, 87, -71, -122, -63, 29, -98}, new byte[]{-31, -8, -104, 17, 105, -39, -114, -108, -101, 30, -121, -23, -50, 85, 40, -33}, new byte[]{-116, -95, -119, 13, -65, -26, 66, 104, 65, -103, 45, 15, -80, 84, -69, 22}};

    static byte sBox(byte x) {
        return S[(x & 255) >>> 4][x & 15];
    }

    static byte[] subBytes(byte[] s) {
        byte[] out = new byte[s.length];
        out[0] = sBox(s[0]);
        out[1] = sBox(s[1]);
        out[2] = sBox(s[2]);
        out[3] = sBox(s[3]);
        out[4] = sBox(s[4]);
        out[5] = sBox(s[5]);
        out[6] = sBox(s[6]);
        out[7] = sBox(s[7]);
        out[8] = sBox(s[8]);
        out[9] = sBox(s[9]);
        out[10] = sBox(s[10]);
        out[11] = sBox(s[11]);
        out[12] = sBox(s[12]);
        out[13] = sBox(s[13]);
        out[14] = sBox(s[14]);
        out[15] = sBox(s[15]);
        return out;
    }

    static byte[] shiftRows(byte[] s) {
        return new byte[]{s[0], s[5], s[10], s[15], s[4], s[9], s[14], s[3], s[8], s[13], s[2], s[7], s[12], s[1], s[6], s[11]};
    }

    static byte[] aesEnc(byte[] s, byte[] rk) {
        byte[] s2 = mixColumns(shiftRows(subBytes(s)));
        xorReverse(s2, rk);
        return s2;
    }

    static byte xTime(byte x) {
        if ((x >>> 7) > 0) {
            return (byte) (((x << 1) ^ 27) & GF2Field.MASK);
        }
        return (byte) ((x << 1) & GF2Field.MASK);
    }

    static void xorReverse(byte[] x, byte[] y) {
        x[0] = (byte) (x[0] ^ y[15]);
        x[1] = (byte) (x[1] ^ y[14]);
        x[2] = (byte) (x[2] ^ y[13]);
        x[3] = (byte) (x[3] ^ y[12]);
        x[4] = (byte) (x[4] ^ y[11]);
        x[5] = (byte) (x[5] ^ y[10]);
        x[6] = (byte) (x[6] ^ y[9]);
        x[7] = (byte) (x[7] ^ y[8]);
        x[8] = (byte) (x[8] ^ y[7]);
        x[9] = (byte) (x[9] ^ y[6]);
        x[10] = (byte) (x[10] ^ y[5]);
        x[11] = (byte) (x[11] ^ y[4]);
        x[12] = (byte) (x[12] ^ y[3]);
        x[13] = (byte) (x[13] ^ y[2]);
        x[14] = (byte) (x[14] ^ y[1]);
        x[15] = (byte) (x[15] ^ y[0]);
    }

    static byte[] xor(byte[] x, byte[] y, int yStart) {
        byte[] out = new byte[16];
        int i = 0;
        while (i < out.length) {
            out[i] = (byte) (x[i] ^ y[yStart]);
            i++;
            yStart++;
        }
        return out;
    }

    private static byte[] mixColumns(byte[] s) {
        byte[] out = new byte[s.length];
        int j = 0;
        for (int i = 0; i < 4; i++) {
            int j2 = j + 1;
            out[j] = (byte) ((((xTime(s[i * 4]) ^ xTime(s[(i * 4) + 1])) ^ s[(i * 4) + 1]) ^ s[(i * 4) + 2]) ^ s[(i * 4) + 3]);
            int j3 = j2 + 1;
            out[j2] = (byte) ((((s[i * 4] ^ xTime(s[(i * 4) + 1])) ^ xTime(s[(i * 4) + 2])) ^ s[(i * 4) + 2]) ^ s[(i * 4) + 3]);
            int j4 = j3 + 1;
            out[j3] = (byte) ((((s[i * 4] ^ s[(i * 4) + 1]) ^ xTime(s[(i * 4) + 2])) ^ xTime(s[(i * 4) + 3])) ^ s[(i * 4) + 3]);
            j = j4 + 1;
            out[j4] = (byte) ((((xTime(s[i * 4]) ^ s[i * 4]) ^ s[(i * 4) + 1]) ^ s[(i * 4) + 2]) ^ xTime(s[(i * 4) + 3]));
        }
        return out;
    }

    @Override // com.mi.car.jsse.easysec.crypto.Digest
    public int getDigestSize() {
        return 32;
    }
}
