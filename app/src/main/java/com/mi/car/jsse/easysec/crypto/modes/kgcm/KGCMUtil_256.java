package com.mi.car.jsse.easysec.crypto.modes.kgcm;

import com.mi.car.jsse.easysec.math.raw.Interleave;

public class KGCMUtil_256 {
    public static final int SIZE = 4;

    public static void add(long[] x, long[] y, long[] z) {
        z[0] = x[0] ^ y[0];
        z[1] = x[1] ^ y[1];
        z[2] = x[2] ^ y[2];
        z[3] = x[3] ^ y[3];
    }

    public static void copy(long[] x, long[] z) {
        z[0] = x[0];
        z[1] = x[1];
        z[2] = x[2];
        z[3] = x[3];
    }

    public static boolean equal(long[] x, long[] y) {
        return ((((0 | (x[0] ^ y[0])) | (x[1] ^ y[1])) | (x[2] ^ y[2])) | (x[3] ^ y[3])) == 0;
    }

    public static void multiply(long[] x, long[] y, long[] z) {
        long x0 = x[0];
        long x1 = x[1];
        long x2 = x[2];
        long x3 = x[3];
        long y0 = y[0];
        long y1 = y[1];
        long y2 = y[2];
        long y3 = y[3];
        long z0 = 0;
        long z1 = 0;
        long z2 = 0;
        long z3 = 0;
        long z4 = 0;
        for (int j = 0; j < 64; j++) {
            long m0 = -(1 & x0);
            x0 >>>= 1;
            z0 ^= y0 & m0;
            long m1 = -(1 & x1);
            x1 >>>= 1;
            z1 = (z1 ^ (y1 & m0)) ^ (y0 & m1);
            z2 = (z2 ^ (y2 & m0)) ^ (y1 & m1);
            z3 = (z3 ^ (y3 & m0)) ^ (y2 & m1);
            z4 ^= y3 & m1;
            long c = y3 >> 63;
            y3 = (y3 << 1) | (y2 >>> 63);
            y2 = (y2 << 1) | (y1 >>> 63);
            y1 = (y1 << 1) | (y0 >>> 63);
            y0 = (y0 << 1) ^ (1061 & c);
        }
        long y32 = y2;
        long y22 = y1;
        long y12 = (((y3 >>> 62) ^ y0) ^ (y3 >>> 59)) ^ (y3 >>> 54);
        long y02 = (((y3 << 2) ^ y3) ^ (y3 << 5)) ^ (y3 << 10);
        for (int j2 = 0; j2 < 64; j2++) {
            long m2 = -(1 & x2);
            x2 >>>= 1;
            z0 ^= y02 & m2;
            long m3 = -(1 & x3);
            x3 >>>= 1;
            z1 = (z1 ^ (y12 & m2)) ^ (y02 & m3);
            z2 = (z2 ^ (y22 & m2)) ^ (y12 & m3);
            z3 = (z3 ^ (y32 & m2)) ^ (y22 & m3);
            z4 ^= y32 & m3;
            long c2 = y32 >> 63;
            y32 = (y32 << 1) | (y22 >>> 63);
            y22 = (y22 << 1) | (y12 >>> 63);
            y12 = (y12 << 1) | (y02 >>> 63);
            y02 = (y02 << 1) ^ (1061 & c2);
        }
        z[0] = z0 ^ ((((z4 << 2) ^ z4) ^ (z4 << 5)) ^ (z4 << 10));
        z[1] = z1 ^ (((z4 >>> 62) ^ (z4 >>> 59)) ^ (z4 >>> 54));
        z[2] = z2;
        z[3] = z3;
    }

    public static void multiplyX(long[] x, long[] z) {
        long x0 = x[0];
        long x1 = x[1];
        long x2 = x[2];
        long x3 = x[3];
        z[0] = (x0 << 1) ^ (1061 & (x3 >> 63));
        z[1] = (x1 << 1) | (x0 >>> 63);
        z[2] = (x2 << 1) | (x1 >>> 63);
        z[3] = (x3 << 1) | (x2 >>> 63);
    }

    public static void multiplyX8(long[] x, long[] z) {
        long x0 = x[0];
        long x1 = x[1];
        long x2 = x[2];
        long x3 = x[3];
        long c = x3 >>> 56;
        z[0] = ((((x0 << 8) ^ c) ^ (c << 2)) ^ (c << 5)) ^ (c << 10);
        z[1] = (x1 << 8) | (x0 >>> 56);
        z[2] = (x2 << 8) | (x1 >>> 56);
        z[3] = (x3 << 8) | (x2 >>> 56);
    }

    public static void one(long[] z) {
        z[0] = 1;
        z[1] = 0;
        z[2] = 0;
        z[3] = 0;
    }

    public static void square(long[] x, long[] z) {
        long[] t = new long[8];
        for (int i = 0; i < 4; i++) {
            Interleave.expand64To128(x[i], t, i << 1);
        }
        int j = 8;
        while (true) {
            j--;
            if (j >= 4) {
                long n = t[j];
                int i2 = j - 4;
                t[i2] = t[i2] ^ ((((n << 2) ^ n) ^ (n << 5)) ^ (n << 10));
                int i3 = (j - 4) + 1;
                t[i3] = t[i3] ^ (((n >>> 62) ^ (n >>> 59)) ^ (n >>> 54));
            } else {
                copy(t, z);
                return;
            }
        }
    }

    public static void x(long[] z) {
        z[0] = 2;
        z[1] = 0;
        z[2] = 0;
        z[3] = 0;
    }

    public static void zero(long[] z) {
        z[0] = 0;
        z[1] = 0;
        z[2] = 0;
        z[3] = 0;
    }
}
