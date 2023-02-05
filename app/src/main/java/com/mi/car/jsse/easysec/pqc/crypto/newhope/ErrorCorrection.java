package com.mi.car.jsse.easysec.pqc.crypto.newhope;

import com.mi.car.jsse.easysec.util.Arrays;

class ErrorCorrection {
    ErrorCorrection() {
    }

    static int abs(int v) {
        int mask = v >> 31;
        return (v ^ mask) - mask;
    }

    static int f(int[] v, int off0, int off1, int x) {
        int t = (x * 2730) >> 25;
        int t2 = t - ((12288 - (x - (t * 12289))) >> 31);
        v[off0] = (t2 >> 1) + (t2 & 1);
        int t3 = t2 - 1;
        v[off1] = (t3 >> 1) + (t3 & 1);
        return abs(x - ((v[off0] * 2) * 12289));
    }

    static int g(int x) {
        int t = (x * 2730) >> 27;
        int t2 = t - ((49155 - (x - (49156 * t))) >> 31);
        return abs((((t2 >> 1) + (t2 & 1)) * 98312) - x);
    }

    static void helpRec(short[] c, short[] v, byte[] seed, byte nonce) {
        byte[] iv = new byte[8];
        iv[0] = nonce;
        byte[] rand = new byte[32];
        ChaCha20.process(seed, iv, rand, 0, rand.length);
        int[] vs = new int[8];
        int[] vTmp = new int[4];
        for (int i = 0; i < 256; i++) {
            int rBit = (rand[i >>> 3] >>> (i & 7)) & 1;
            int k = (24577 - (((f(vs, 0, 4, (v[i + 0] * 8) + (rBit * 4)) + f(vs, 1, 5, (v[i + 256] * 8) + (rBit * 4))) + f(vs, 2, 6, (v[i + 512] * 8) + (rBit * 4))) + f(vs, 3, 7, (v[i + 768] * 8) + (rBit * 4)))) >> 31;
            vTmp[0] = ((k ^ -1) & vs[0]) ^ (vs[4] & k);
            vTmp[1] = ((k ^ -1) & vs[1]) ^ (vs[5] & k);
            vTmp[2] = ((k ^ -1) & vs[2]) ^ (vs[6] & k);
            vTmp[3] = ((k ^ -1) & vs[3]) ^ (vs[7] & k);
            c[i + 0] = (short) ((vTmp[0] - vTmp[3]) & 3);
            c[i + 256] = (short) ((vTmp[1] - vTmp[3]) & 3);
            c[i + 512] = (short) ((vTmp[2] - vTmp[3]) & 3);
            c[i + 768] = (short) (((-k) + (vTmp[3] * 2)) & 3);
        }
    }

    static short LDDecode(int xi0, int xi1, int xi2, int xi3) {
        return (short) (((((g(xi0) + g(xi1)) + g(xi2)) + g(xi3)) - 98312) >>> 31);
    }

    static void rec(byte[] key, short[] v, short[] c) {
        Arrays.fill(key, (byte) 0);
        int[] tmp = new int[4];
        for (int i = 0; i < 256; i++) {
            tmp[0] = ((v[i + 0] * 8) + 196624) - (((c[i + 0] * 2) + c[i + 768]) * 12289);
            tmp[1] = ((v[i + 256] * 8) + 196624) - (((c[i + 256] * 2) + c[i + 768]) * 12289);
            tmp[2] = ((v[i + 512] * 8) + 196624) - (((c[i + 512] * 2) + c[i + 768]) * 12289);
            tmp[3] = ((v[i + 768] * 8) + 196624) - (c[i + 768] * 12289);
            int i2 = i >>> 3;
            key[i2] = (byte) (key[i2] | (LDDecode(tmp[0], tmp[1], tmp[2], tmp[3]) << (i & 7)));
        }
    }
}
