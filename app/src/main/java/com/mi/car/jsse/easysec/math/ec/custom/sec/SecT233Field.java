package com.mi.car.jsse.easysec.math.ec.custom.sec;

import com.mi.car.jsse.easysec.math.raw.Interleave;
import com.mi.car.jsse.easysec.math.raw.Nat;
import com.mi.car.jsse.easysec.math.raw.Nat256;
import java.math.BigInteger;

public class SecT233Field {
    private static final long M41 = 2199023255551L;
    private static final long M59 = 576460752303423487L;

    public static void add(long[] x, long[] y, long[] z) {
        z[0] = x[0] ^ y[0];
        z[1] = x[1] ^ y[1];
        z[2] = x[2] ^ y[2];
        z[3] = x[3] ^ y[3];
    }

    public static void addExt(long[] xx, long[] yy, long[] zz) {
        zz[0] = xx[0] ^ yy[0];
        zz[1] = xx[1] ^ yy[1];
        zz[2] = xx[2] ^ yy[2];
        zz[3] = xx[3] ^ yy[3];
        zz[4] = xx[4] ^ yy[4];
        zz[5] = xx[5] ^ yy[5];
        zz[6] = xx[6] ^ yy[6];
        zz[7] = xx[7] ^ yy[7];
    }

    public static void addOne(long[] x, long[] z) {
        z[0] = x[0] ^ 1;
        z[1] = x[1];
        z[2] = x[2];
        z[3] = x[3];
    }

    private static void addTo(long[] x, long[] z) {
        z[0] = z[0] ^ x[0];
        z[1] = z[1] ^ x[1];
        z[2] = z[2] ^ x[2];
        z[3] = z[3] ^ x[3];
    }

    public static long[] fromBigInteger(BigInteger x) {
        return Nat.fromBigInteger64(233, x);
    }

    public static void halfTrace(long[] x, long[] z) {
        long[] tt = Nat256.createExt64();
        Nat256.copy64(x, z);
        for (int i = 1; i < 233; i += 2) {
            implSquare(z, tt);
            reduce(tt, z);
            implSquare(z, tt);
            reduce(tt, z);
            addTo(x, z);
        }
    }

    public static void invert(long[] x, long[] z) {
        if (Nat256.isZero64(x)) {
            throw new IllegalStateException();
        }
        long[] t0 = Nat256.create64();
        long[] t1 = Nat256.create64();
        square(x, t0);
        multiply(t0, x, t0);
        square(t0, t0);
        multiply(t0, x, t0);
        squareN(t0, 3, t1);
        multiply(t1, t0, t1);
        square(t1, t1);
        multiply(t1, x, t1);
        squareN(t1, 7, t0);
        multiply(t0, t1, t0);
        squareN(t0, 14, t1);
        multiply(t1, t0, t1);
        square(t1, t1);
        multiply(t1, x, t1);
        squareN(t1, 29, t0);
        multiply(t0, t1, t0);
        squareN(t0, 58, t1);
        multiply(t1, t0, t1);
        squareN(t1, 116, t0);
        multiply(t0, t1, t0);
        square(t0, z);
    }

    public static void multiply(long[] x, long[] y, long[] z) {
        long[] tt = Nat256.createExt64();
        implMultiply(x, y, tt);
        reduce(tt, z);
    }

    public static void multiplyAddToExt(long[] x, long[] y, long[] zz) {
        long[] tt = Nat256.createExt64();
        implMultiply(x, y, tt);
        addExt(zz, tt, zz);
    }

    public static void reduce(long[] xx, long[] z) {
        long x0 = xx[0];
        long x1 = xx[1];
        long x2 = xx[2];
        long x3 = xx[3];
        long x4 = xx[4];
        long x5 = xx[5];
        long x6 = xx[6];
        long x7 = xx[7];
        long x52 = x5 ^ (x7 >>> 31);
        long x42 = (x4 ^ ((x7 >>> 41) ^ (x7 << 33))) ^ (x6 >>> 31);
        long x32 = ((x3 ^ (x7 << 23)) ^ ((x6 >>> 41) ^ (x6 << 33))) ^ (x52 >>> 31);
        long t = x32 >>> 41;
        z[0] = (x0 ^ (x42 << 23)) ^ t;
        z[1] = (t << 10) ^ ((x1 ^ (x52 << 23)) ^ ((x42 >>> 41) ^ (x42 << 33)));
        z[2] = ((x2 ^ (x6 << 23)) ^ ((x52 >>> 41) ^ (x52 << 33))) ^ (x42 >>> 31);
        z[3] = M41 & x32;
    }

    public static void reduce23(long[] z, int zOff) {
        long z3 = z[zOff + 3];
        long t = z3 >>> 41;
        z[zOff] = z[zOff] ^ t;
        int i = zOff + 1;
        z[i] = z[i] ^ (t << 10);
        z[zOff + 3] = M41 & z3;
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
        long c2 = c1 >>> 27;
        long c12 = c1 ^ ((c0 >>> 27) | (c1 << 37));
        long c02 = c0 ^ (c0 << 37);
        long[] tt = Nat256.createExt64();
        int[] shifts = {32, 117, 191};
        for (int i = 0; i < shifts.length; i++) {
            int w = shifts[i] >>> 6;
            int s = shifts[i] & 63;
            tt[w] = tt[w] ^ (c02 << s);
            int i2 = w + 1;
            tt[i2] = tt[i2] ^ ((c12 << s) | (c02 >>> (-s)));
            int i3 = w + 2;
            tt[i3] = tt[i3] ^ ((c2 << s) | (c12 >>> (-s)));
            int i4 = w + 3;
            tt[i4] = tt[i4] ^ (c2 >>> (-s));
        }
        reduce(tt, z);
        z[0] = z[0] ^ e0;
        z[1] = z[1] ^ e1;
    }

    public static void square(long[] x, long[] z) {
        long[] tt = Nat256.createExt64();
        implSquare(x, tt);
        reduce(tt, z);
    }

    public static void squareAddToExt(long[] x, long[] zz) {
        long[] tt = Nat256.createExt64();
        implSquare(x, tt);
        addExt(zz, tt, zz);
    }

    public static void squareN(long[] x, int n, long[] z) {
        long[] tt = Nat256.createExt64();
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
        return ((int) (x[0] ^ (x[2] >>> 31))) & 1;
    }

    protected static void implCompactExt(long[] zz) {
        long z0 = zz[0];
        long z1 = zz[1];
        long z2 = zz[2];
        long z3 = zz[3];
        long z4 = zz[4];
        long z5 = zz[5];
        long z6 = zz[6];
        long z7 = zz[7];
        zz[0] = (z1 << 59) ^ z0;
        zz[1] = (z1 >>> 5) ^ (z2 << 54);
        zz[2] = (z2 >>> 10) ^ (z3 << 49);
        zz[3] = (z3 >>> 15) ^ (z4 << 44);
        zz[4] = (z4 >>> 20) ^ (z5 << 39);
        zz[5] = (z5 >>> 25) ^ (z6 << 34);
        zz[6] = (z6 >>> 30) ^ (z7 << 29);
        zz[7] = z7 >>> 35;
    }

    protected static void implExpand(long[] x, long[] z) {
        long x0 = x[0];
        long x1 = x[1];
        long x2 = x[2];
        long x3 = x[3];
        z[0] = M59 & x0;
        z[1] = ((x0 >>> 59) ^ (x1 << 5)) & M59;
        z[2] = ((x1 >>> 54) ^ (x2 << 10)) & M59;
        z[3] = (x2 >>> 49) ^ (x3 << 15);
    }

    protected static void implMultiply(long[] x, long[] y, long[] zz) {
        long[] f = new long[4];
        long[] g = new long[4];
        implExpand(x, f);
        implExpand(y, g);
        long[] u = new long[8];
        implMulwAcc(u, f[0], g[0], zz, 0);
        implMulwAcc(u, f[1], g[1], zz, 1);
        implMulwAcc(u, f[2], g[2], zz, 2);
        implMulwAcc(u, f[3], g[3], zz, 3);
        for (int i = 5; i > 0; i--) {
            zz[i] = zz[i] ^ zz[i - 1];
        }
        implMulwAcc(u, f[0] ^ f[1], g[0] ^ g[1], zz, 1);
        implMulwAcc(u, f[2] ^ f[3], g[2] ^ g[3], zz, 3);
        for (int i2 = 7; i2 > 1; i2--) {
            zz[i2] = zz[i2] ^ zz[i2 - 2];
        }
        long c0 = f[0] ^ f[2];
        long c1 = f[1] ^ f[3];
        long d0 = g[0] ^ g[2];
        long d1 = g[1] ^ g[3];
        implMulwAcc(u, c0 ^ c1, d0 ^ d1, zz, 3);
        long[] t = new long[3];
        implMulwAcc(u, c0, d0, t, 0);
        implMulwAcc(u, c1, d1, t, 1);
        long t0 = t[0];
        long t1 = t[1];
        long t2 = t[2];
        zz[2] = zz[2] ^ t0;
        zz[3] = zz[3] ^ (t0 ^ t1);
        zz[4] = zz[4] ^ (t2 ^ t1);
        zz[5] = zz[5] ^ t2;
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
        Interleave.expand64To128(x, 0, 4, zz, 0);
    }
}
