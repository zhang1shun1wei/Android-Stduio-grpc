package com.mi.car.jsse.easysec.math.ec.custom.sec;

import com.mi.car.jsse.easysec.asn1.BERTags;
import com.mi.car.jsse.easysec.math.raw.Interleave;
import com.mi.car.jsse.easysec.math.raw.Nat;
import com.mi.car.jsse.easysec.math.raw.Nat448;
import java.math.BigInteger;

public class SecT409Field {
    private static final long M25 = 33554431;
    private static final long M59 = 576460752303423487L;

    public static void add(long[] x, long[] y, long[] z) {
        z[0] = x[0] ^ y[0];
        z[1] = x[1] ^ y[1];
        z[2] = x[2] ^ y[2];
        z[3] = x[3] ^ y[3];
        z[4] = x[4] ^ y[4];
        z[5] = x[5] ^ y[5];
        z[6] = x[6] ^ y[6];
    }

    public static void addExt(long[] xx, long[] yy, long[] zz) {
        for (int i = 0; i < 13; i++) {
            zz[i] = xx[i] ^ yy[i];
        }
    }

    public static void addOne(long[] x, long[] z) {
        z[0] = x[0] ^ 1;
        z[1] = x[1];
        z[2] = x[2];
        z[3] = x[3];
        z[4] = x[4];
        z[5] = x[5];
        z[6] = x[6];
    }

    private static void addTo(long[] x, long[] z) {
        z[0] = z[0] ^ x[0];
        z[1] = z[1] ^ x[1];
        z[2] = z[2] ^ x[2];
        z[3] = z[3] ^ x[3];
        z[4] = z[4] ^ x[4];
        z[5] = z[5] ^ x[5];
        z[6] = z[6] ^ x[6];
    }

    public static long[] fromBigInteger(BigInteger x) {
        return Nat.fromBigInteger64(409, x);
    }

    public static void halfTrace(long[] x, long[] z) {
        long[] tt = Nat.create64(13);
        Nat448.copy64(x, z);
        for (int i = 1; i < 409; i += 2) {
            implSquare(z, tt);
            reduce(tt, z);
            implSquare(z, tt);
            reduce(tt, z);
            addTo(x, z);
        }
    }

    public static void invert(long[] x, long[] z) {
        if (Nat448.isZero64(x)) {
            throw new IllegalStateException();
        }
        long[] t0 = Nat448.create64();
        long[] t1 = Nat448.create64();
        long[] t2 = Nat448.create64();
        square(x, t0);
        squareN(t0, 1, t1);
        multiply(t0, t1, t0);
        squareN(t1, 1, t1);
        multiply(t0, t1, t0);
        squareN(t0, 3, t1);
        multiply(t0, t1, t0);
        squareN(t0, 6, t1);
        multiply(t0, t1, t0);
        squareN(t0, 12, t1);
        multiply(t0, t1, t2);
        squareN(t2, 24, t0);
        squareN(t0, 24, t1);
        multiply(t0, t1, t0);
        squareN(t0, 48, t1);
        multiply(t0, t1, t0);
        squareN(t0, 96, t1);
        multiply(t0, t1, t0);
        squareN(t0, BERTags.PRIVATE, t1);
        multiply(t0, t1, t0);
        multiply(t0, t2, z);
    }

    public static void multiply(long[] x, long[] y, long[] z) {
        long[] tt = Nat448.createExt64();
        implMultiply(x, y, tt);
        reduce(tt, z);
    }

    public static void multiplyAddToExt(long[] x, long[] y, long[] zz) {
        long[] tt = Nat448.createExt64();
        implMultiply(x, y, tt);
        addExt(zz, tt, zz);
    }

    public static void reduce(long[] xx, long[] z) {
        long x00 = xx[0];
        long x01 = xx[1];
        long x02 = xx[2];
        long x03 = xx[3];
        long x04 = xx[4];
        long x05 = xx[5];
        long x06 = xx[6];
        long x07 = xx[7];
        long u = xx[12];
        long x052 = x05 ^ (u << 39);
        long x062 = x06 ^ ((u >>> 25) ^ (u << 62));
        long x072 = x07 ^ (u >>> 2);
        long u2 = xx[11];
        long x042 = x04 ^ (u2 << 39);
        long x053 = x052 ^ ((u2 >>> 25) ^ (u2 << 62));
        long x063 = x062 ^ (u2 >>> 2);
        long u3 = xx[10];
        long x032 = x03 ^ (u3 << 39);
        long x043 = x042 ^ ((u3 >>> 25) ^ (u3 << 62));
        long x054 = x053 ^ (u3 >>> 2);
        long u4 = xx[9];
        long x022 = x02 ^ (u4 << 39);
        long x033 = x032 ^ ((u4 >>> 25) ^ (u4 << 62));
        long x044 = x043 ^ (u4 >>> 2);
        long u5 = xx[8];
        long t = x063 >>> 25;
        z[0] = (x00 ^ (x072 << 39)) ^ t;
        z[1] = (t << 23) ^ ((x01 ^ (u5 << 39)) ^ ((x072 >>> 25) ^ (x072 << 62)));
        z[2] = (x022 ^ ((u5 >>> 25) ^ (u5 << 62))) ^ (x072 >>> 2);
        z[3] = x033 ^ (u5 >>> 2);
        z[4] = x044;
        z[5] = x054;
        z[6] = M25 & x063;
    }

    public static void reduce39(long[] z, int zOff) {
        long z6 = z[zOff + 6];
        long t = z6 >>> 25;
        z[zOff] = z[zOff] ^ t;
        int i = zOff + 1;
        z[i] = z[i] ^ (t << 23);
        z[zOff + 6] = M25 & z6;
    }

    public static void sqrt(long[] x, long[] z) {
        long u0 = Interleave.unshuffle(x[0]);
        long u1 = Interleave.unshuffle(x[1]);
        long e0 = (4294967295L & u0) | (u1 << 32);
        long c0 = (u0 >>> 32) | (-4294967296L & u1);
        long u02 = Interleave.unshuffle(x[2]);
        long u12 = Interleave.unshuffle(x[3]);
        long e1 = (4294967295L & u02) | (u12 << 32);
        long c1 = (u02 >>> 32) | (-4294967296L & u12);
        long u03 = Interleave.unshuffle(x[4]);
        long u13 = Interleave.unshuffle(x[5]);
        long e2 = (4294967295L & u03) | (u13 << 32);
        long c2 = (u03 >>> 32) | (-4294967296L & u13);
        long u04 = Interleave.unshuffle(x[6]);
        long c3 = u04 >>> 32;
        z[0] = (c0 << 44) ^ e0;
        z[1] = ((c1 << 44) ^ e1) ^ (c0 >>> 20);
        z[2] = ((c2 << 44) ^ e2) ^ (c1 >>> 20);
        z[3] = (((c3 << 44) ^ (u04 & 4294967295L)) ^ (c2 >>> 20)) ^ (c0 << 13);
        z[4] = ((c3 >>> 20) ^ (c1 << 13)) ^ (c0 >>> 51);
        z[5] = (c2 << 13) ^ (c1 >>> 51);
        z[6] = (c3 << 13) ^ (c2 >>> 51);
    }

    public static void square(long[] x, long[] z) {
        long[] tt = Nat.create64(13);
        implSquare(x, tt);
        reduce(tt, z);
    }

    public static void squareAddToExt(long[] x, long[] zz) {
        long[] tt = Nat.create64(13);
        implSquare(x, tt);
        addExt(zz, tt, zz);
    }

    public static void squareN(long[] x, int n, long[] z) {
        long[] tt = Nat.create64(13);
        implSquare(x, tt);
        reduce(tt, z);
        while (true) {
            n--;
            if (n > 0) {
                implSquare(z, tt);
                reduce(tt, z);
            } else {
                return;
            }
        }
    }

    public static int trace(long[] x) {
        return ((int) x[0]) & 1;
    }

    protected static void implCompactExt(long[] zz) {
        long z00 = zz[0];
        long z01 = zz[1];
        long z02 = zz[2];
        long z03 = zz[3];
        long z04 = zz[4];
        long z05 = zz[5];
        long z06 = zz[6];
        long z07 = zz[7];
        long z08 = zz[8];
        long z09 = zz[9];
        long z10 = zz[10];
        long z11 = zz[11];
        long z12 = zz[12];
        long z13 = zz[13];
        zz[0] = (z01 << 59) ^ z00;
        zz[1] = (z01 >>> 5) ^ (z02 << 54);
        zz[2] = (z02 >>> 10) ^ (z03 << 49);
        zz[3] = (z03 >>> 15) ^ (z04 << 44);
        zz[4] = (z04 >>> 20) ^ (z05 << 39);
        zz[5] = (z05 >>> 25) ^ (z06 << 34);
        zz[6] = (z06 >>> 30) ^ (z07 << 29);
        zz[7] = (z07 >>> 35) ^ (z08 << 24);
        zz[8] = (z08 >>> 40) ^ (z09 << 19);
        zz[9] = (z09 >>> 45) ^ (z10 << 14);
        zz[10] = (z10 >>> 50) ^ (z11 << 9);
        zz[11] = ((z11 >>> 55) ^ (z12 << 4)) ^ (z13 << 63);
        zz[12] = z13 >>> 1;
    }

    protected static void implExpand(long[] x, long[] z) {
        long x0 = x[0];
        long x1 = x[1];
        long x2 = x[2];
        long x3 = x[3];
        long x4 = x[4];
        long x5 = x[5];
        long x6 = x[6];
        z[0] = M59 & x0;
        z[1] = ((x0 >>> 59) ^ (x1 << 5)) & M59;
        z[2] = ((x1 >>> 54) ^ (x2 << 10)) & M59;
        z[3] = ((x2 >>> 49) ^ (x3 << 15)) & M59;
        z[4] = ((x3 >>> 44) ^ (x4 << 20)) & M59;
        z[5] = ((x4 >>> 39) ^ (x5 << 25)) & M59;
        z[6] = (x5 >>> 34) ^ (x6 << 30);
    }

    protected static void implMultiply(long[] x, long[] y, long[] zz) {
        long[] a = new long[7];
        long[] b = new long[7];
        implExpand(x, a);
        implExpand(y, b);
        long[] u = new long[8];
        for (int i = 0; i < 7; i++) {
            implMulwAcc(u, a[i], b[i], zz, i << 1);
        }
        long v0 = zz[0];
        long v1 = zz[1];
        long v02 = v0 ^ zz[2];
        zz[1] = v02 ^ v1;
        long v12 = v1 ^ zz[3];
        long v03 = v02 ^ zz[4];
        zz[2] = v03 ^ v12;
        long v13 = v12 ^ zz[5];
        long v04 = v03 ^ zz[6];
        zz[3] = v04 ^ v13;
        long v14 = v13 ^ zz[7];
        long v05 = v04 ^ zz[8];
        zz[4] = v05 ^ v14;
        long v15 = v14 ^ zz[9];
        long v06 = v05 ^ zz[10];
        zz[5] = v06 ^ v15;
        long v16 = v15 ^ zz[11];
        long v07 = v06 ^ zz[12];
        zz[6] = v07 ^ v16;
        long w = v07 ^ (v16 ^ zz[13]);
        zz[7] = zz[0] ^ w;
        zz[8] = zz[1] ^ w;
        zz[9] = zz[2] ^ w;
        zz[10] = zz[3] ^ w;
        zz[11] = zz[4] ^ w;
        zz[12] = zz[5] ^ w;
        zz[13] = zz[6] ^ w;
        implMulwAcc(u, a[0] ^ a[1], b[0] ^ b[1], zz, 1);
        implMulwAcc(u, a[0] ^ a[2], b[0] ^ b[2], zz, 2);
        implMulwAcc(u, a[0] ^ a[3], b[0] ^ b[3], zz, 3);
        implMulwAcc(u, a[1] ^ a[2], b[1] ^ b[2], zz, 3);
        implMulwAcc(u, a[0] ^ a[4], b[0] ^ b[4], zz, 4);
        implMulwAcc(u, a[1] ^ a[3], b[1] ^ b[3], zz, 4);
        implMulwAcc(u, a[0] ^ a[5], b[0] ^ b[5], zz, 5);
        implMulwAcc(u, a[1] ^ a[4], b[1] ^ b[4], zz, 5);
        implMulwAcc(u, a[2] ^ a[3], b[2] ^ b[3], zz, 5);
        implMulwAcc(u, a[0] ^ a[6], b[0] ^ b[6], zz, 6);
        implMulwAcc(u, a[1] ^ a[5], b[1] ^ b[5], zz, 6);
        implMulwAcc(u, a[2] ^ a[4], b[2] ^ b[4], zz, 6);
        implMulwAcc(u, a[1] ^ a[6], b[1] ^ b[6], zz, 7);
        implMulwAcc(u, a[2] ^ a[5], b[2] ^ b[5], zz, 7);
        implMulwAcc(u, a[3] ^ a[4], b[3] ^ b[4], zz, 7);
        implMulwAcc(u, a[2] ^ a[6], b[2] ^ b[6], zz, 8);
        implMulwAcc(u, a[3] ^ a[5], b[3] ^ b[5], zz, 8);
        implMulwAcc(u, a[3] ^ a[6], b[3] ^ b[6], zz, 9);
        implMulwAcc(u, a[4] ^ a[5], b[4] ^ b[5], zz, 9);
        implMulwAcc(u, a[4] ^ a[6], b[4] ^ b[6], zz, 10);
        implMulwAcc(u, a[5] ^ a[6], b[5] ^ b[6], zz, 11);
        implCompactExt(zz);
    }

    protected static void implMulwAcc(long[] u, long x, long y, long[] z, int zOff) {
        u[1] = y;
        u[2] = u[1] << 1;
        u[3] = u[2] ^ y;
        u[4] = u[2] << 1;
        u[5] = u[4] ^ y;
        u[6] = u[3] << 1;
        u[7] = u[6] ^ y;
        int j = (int) x;
        long h = 0;
        long l = u[j & 7] ^ (u[(j >>> 3) & 7] << 3);
        int k = 54;
        do {
            int j2 = (int) (x >>> k);
            long g = u[j2 & 7] ^ (u[(j2 >>> 3) & 7] << 3);
            l ^= g << k;
            h ^= g >>> (-k);
            k -= 6;
        } while (k > 0);
        z[zOff] = z[zOff] ^ (M59 & l);
        int i = zOff + 1;
        z[i] = z[i] ^ ((l >>> 59) ^ (h << 5));
    }

    protected static void implSquare(long[] x, long[] zz) {
        Interleave.expand64To128(x, 0, 6, zz, 0);
        zz[12] = Interleave.expand32to64((int) x[6]);
    }
}
