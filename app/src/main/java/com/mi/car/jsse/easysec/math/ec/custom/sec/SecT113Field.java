package com.mi.car.jsse.easysec.math.ec.custom.sec;

import com.mi.car.jsse.easysec.math.raw.Interleave;
import com.mi.car.jsse.easysec.math.raw.Nat;
import com.mi.car.jsse.easysec.math.raw.Nat128;
import java.math.BigInteger;

public class SecT113Field {
    private static final long M49 = 562949953421311L;
    private static final long M57 = 144115188075855871L;

    public static void add(long[] x, long[] y, long[] z) {
        z[0] = x[0] ^ y[0];
        z[1] = x[1] ^ y[1];
    }

    public static void addExt(long[] xx, long[] yy, long[] zz) {
        zz[0] = xx[0] ^ yy[0];
        zz[1] = xx[1] ^ yy[1];
        zz[2] = xx[2] ^ yy[2];
        zz[3] = xx[3] ^ yy[3];
    }

    public static void addOne(long[] x, long[] z) {
        z[0] = x[0] ^ 1;
        z[1] = x[1];
    }

    private static void addTo(long[] x, long[] z) {
        z[0] = z[0] ^ x[0];
        z[1] = z[1] ^ x[1];
    }

    public static long[] fromBigInteger(BigInteger x) {
        return Nat.fromBigInteger64(113, x);
    }

    public static void halfTrace(long[] x, long[] z) {
        long[] tt = Nat128.createExt64();
        Nat128.copy64(x, z);
        for (int i = 1; i < 113; i += 2) {
            implSquare(z, tt);
            reduce(tt, z);
            implSquare(z, tt);
            reduce(tt, z);
            addTo(x, z);
        }
    }

    public static void invert(long[] x, long[] z) {
        if (Nat128.isZero64(x)) {
            throw new IllegalStateException();
        }
        long[] t0 = Nat128.create64();
        long[] t1 = Nat128.create64();
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
        squareN(t1, 28, t0);
        multiply(t0, t1, t0);
        squareN(t0, 56, t1);
        multiply(t1, t0, t1);
        square(t1, z);
    }

    public static void multiply(long[] x, long[] y, long[] z) {
        long[] tt = new long[8];
        implMultiply(x, y, tt);
        reduce(tt, z);
    }

    public static void multiplyAddToExt(long[] x, long[] y, long[] zz) {
        long[] tt = new long[8];
        implMultiply(x, y, tt);
        addExt(zz, tt, zz);
    }

    public static void reduce(long[] xx, long[] z) {
        long x0 = xx[0];
        long x1 = xx[1];
        long x2 = xx[2];
        long x3 = xx[3];
        long x22 = x2 ^ ((x3 >>> 49) ^ (x3 >>> 40));
        long x12 = (x1 ^ ((x3 << 15) ^ (x3 << 24))) ^ ((x22 >>> 49) ^ (x22 >>> 40));
        long t = x12 >>> 49;
        z[0] = ((x0 ^ ((x22 << 15) ^ (x22 << 24))) ^ t) ^ (t << 9);
        z[1] = M49 & x12;
    }

    public static void reduce15(long[] z, int zOff) {
        long z1 = z[zOff + 1];
        long t = z1 >>> 49;
        z[zOff] = z[zOff] ^ ((t << 9) ^ t);
        z[zOff + 1] = M49 & z1;
    }

    public static void sqrt(long[] x, long[] z) {
        long u0 = Interleave.unshuffle(x[0]);
        long u1 = Interleave.unshuffle(x[1]);
        long c0 = (u0 >>> 32) | (-4294967296L & u1);
        z[0] = ((c0 << 57) ^ ((4294967295L & u0) | (u1 << 32))) ^ (c0 << 5);
        z[1] = (c0 >>> 7) ^ (c0 >>> 59);
    }

    public static void square(long[] x, long[] z) {
        long[] tt = Nat128.createExt64();
        implSquare(x, tt);
        reduce(tt, z);
    }

    public static void squareAddToExt(long[] x, long[] zz) {
        long[] tt = Nat128.createExt64();
        implSquare(x, tt);
        addExt(zz, tt, zz);
    }

    public static void squareN(long[] x, int n, long[] z) {
        long[] tt = Nat128.createExt64();
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

    protected static void implMultiply(long[] x, long[] y, long[] zz) {
        long f0 = x[0];
        long f1 = ((f0 >>> 57) ^ (x[1] << 7)) & M57;
        long f02 = f0 & M57;
        long g0 = y[0];
        long g1 = ((g0 >>> 57) ^ (y[1] << 7)) & M57;
        long g02 = g0 & M57;
        long[] H = new long[6];
        implMulw(zz, f02, g02, H, 0);
        implMulw(zz, f1, g1, H, 2);
        implMulw(zz, f02 ^ f1, g02 ^ g1, H, 4);
        long r = H[1] ^ H[2];
        long z0 = H[0];
        long z3 = H[3];
        long z1 = (H[4] ^ z0) ^ r;
        long z2 = (H[5] ^ z3) ^ r;
        zz[0] = (z1 << 57) ^ z0;
        zz[1] = (z1 >>> 7) ^ (z2 << 50);
        zz[2] = (z2 >>> 14) ^ (z3 << 43);
        zz[3] = z3 >>> 21;
    }

    protected static void implMulw(long[] u, long x, long y, long[] z, int zOff) {
        u[1] = y;
        u[2] = u[1] << 1;
        u[3] = u[2] ^ y;
        u[4] = u[2] << 1;
        u[5] = u[4] ^ y;
        u[6] = u[3] << 1;
        u[7] = u[6] ^ y;
        long h = 0;
        long l = u[((int) x) & 7];
        int k = 48;
        do {
            int j = (int) (x >>> k);
            long g = (u[j & 7] ^ (u[(j >>> 3) & 7] << 3)) ^ (u[(j >>> 6) & 7] << 6);
            l ^= g << k;
            h ^= g >>> (-k);
            k -= 9;
        } while (k > 0);
        z[zOff] = M57 & l;
        z[zOff + 1] = (l >>> 57) ^ ((h ^ (((72198606942111744L & x) & ((y << 7) >> 63)) >>> 8)) << 7);
    }

    protected static void implSquare(long[] x, long[] zz) {
        Interleave.expand64To128(x, 0, 2, zz, 0);
    }
}
