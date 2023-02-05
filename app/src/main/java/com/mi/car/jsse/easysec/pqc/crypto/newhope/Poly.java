package com.mi.car.jsse.easysec.pqc.crypto.newhope;

import com.mi.car.jsse.easysec.crypto.digests.SHAKEDigest;
import com.mi.car.jsse.easysec.pqc.crypto.rainbow.util.GF2Field;
import com.mi.car.jsse.easysec.util.Pack;

/* access modifiers changed from: package-private */
public class Poly {
    Poly() {
    }

    static void add(short[] x, short[] y, short[] z) {
        for (int i = 0; i < 1024; i++) {
            z[i] = Reduce.barrett((short) (x[i] + y[i]));
        }
    }

    static void fromBytes(short[] r, byte[] a) {
        for (int i = 0; i < 256; i++) {
            int j = i * 7;
            int a0 = a[j + 0] & 255;
            int a1 = a[j + 1] & 255;
            int a2 = a[j + 2] & 255;
            int a3 = a[j + 3] & 255;
            int a4 = a[j + 4] & 255;
            int a5 = a[j + 5] & 255;
            int a6 = a[j + 6] & 255;
            int k = i * 4;
            r[k + 0] = (short) (((a1 & 63) << 8) | a0);
            r[k + 1] = (short) ((a1 >>> 6) | (a2 << 2) | ((a3 & 15) << 10));
            r[k + 2] = (short) ((a3 >>> 4) | (a4 << 4) | ((a5 & 3) << 12));
            r[k + 3] = (short) ((a5 >>> 2) | (a6 << 6));
        }
    }

    static void fromNTT(short[] r) {
        NTT.bitReverse(r);
        NTT.core(r, Precomp.OMEGAS_INV_MONTGOMERY);
        NTT.mulCoefficients(r, Precomp.PSIS_INV_MONTGOMERY);
    }

    static void getNoise(short[] r, byte[] seed, byte nonce) {
        byte[] iv = new byte[8];
        iv[0] = nonce;
        byte[] buf = new byte[4096];
        ChaCha20.process(seed, iv, buf, 0, buf.length);
        for (int i = 0; i < 1024; i++) {
            int t = Pack.bigEndianToInt(buf, i * 4);
            int d = 0;
            for (int j = 0; j < 8; j++) {
                d += (t >> j) & 16843009;
            }
            int a = ((d >>> 24) + (d >>> 0)) & GF2Field.MASK;
            r[i] = (short) ((a + 12289) - (((d >>> 16) + (d >>> 8)) & GF2Field.MASK));
        }
    }

    static void pointWise(short[] x, short[] y, short[] z) {
        for (int i = 0; i < 1024; i++) {
            z[i] = Reduce.montgomery((Reduce.montgomery((y[i] & 65535) * 3186) & 65535) * (x[i] & 65535));
        }
    }

    static void toBytes(byte[] r, short[] p) {
        for (int i = 0; i < 256; i++) {
            int j = i * 4;
            short t0 = normalize(p[j + 0]);
            short t1 = normalize(p[j + 1]);
            short t2 = normalize(p[j + 2]);
            short t3 = normalize(p[j + 3]);
            int k = i * 7;
            r[k + 0] = (byte) t0;
            r[k + 1] = (byte) ((t0 >> 8) | (t1 << 6));
            r[k + 2] = (byte) (t1 >> 2);
            r[k + 3] = (byte) ((t1 >> 10) | (t2 << 4));
            r[k + 4] = (byte) (t2 >> 4);
            r[k + 5] = (byte) ((t2 >> 12) | (t3 << 2));
            r[k + 6] = (byte) (t3 >> 6);
        }
    }

    static void toNTT(short[] r) {
        NTT.mulCoefficients(r, Precomp.PSIS_BITREV_MONTGOMERY);
        NTT.core(r, Precomp.OMEGAS_MONTGOMERY);
    }

    static void uniform(short[] a, byte[] seed) {
        SHAKEDigest xof = new SHAKEDigest(128);
        xof.update(seed, 0, seed.length);
        int pos = 0;
        while (true) {
            byte[] output = new byte[256];
            xof.doOutput(output, 0, output.length);
            int i = 0;
            while (true) {
                if (i < output.length) {
                    int val = (output[i] & 255) | ((output[i + 1] & 255) << 8);
                    if (val < 61445) {
                        int pos2 = pos + 1;
                        a[pos] = (short) val;
                        if (pos2 != 1024) {
                            pos = pos2;
                        } else {
                            return;
                        }
                    }
                    i += 2;
                }
            }
        }
    }

    private static short normalize(short x) {
        int t = Reduce.barrett(x);
        int m = t - 12289;
        return (short) (m ^ ((t ^ m) & (m >> 31)));
    }
}
