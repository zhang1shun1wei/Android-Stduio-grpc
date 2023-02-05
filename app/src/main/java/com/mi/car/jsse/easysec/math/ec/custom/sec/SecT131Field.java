package com.mi.car.jsse.easysec.math.ec.custom.sec;

import com.mi.car.jsse.easysec.math.raw.Interleave;
import com.mi.car.jsse.easysec.math.raw.Nat;
import com.mi.car.jsse.easysec.math.raw.Nat192;
import java.math.BigInteger;

public class SecT131Field {
    private static final long M03 = 7;
    private static final long M44 = 17592186044415L;
    private static final long[] ROOT_Z = {2791191049453778211L, 2791191049453778402L, 6};

    public static void add(long[] x, long[] y, long[] z) {
        z[0] = x[0] ^ y[0];
        z[1] = x[1] ^ y[1];
        z[2] = x[2] ^ y[2];
    }

    public static void addExt(long[] xx, long[] yy, long[] zz) {
        zz[0] = xx[0] ^ yy[0];
        zz[1] = xx[1] ^ yy[1];
        zz[2] = xx[2] ^ yy[2];
        zz[3] = xx[3] ^ yy[3];
        zz[4] = xx[4] ^ yy[4];
    }

    public static void addOne(long[] x, long[] z) {
        z[0] = x[0] ^ 1;
        z[1] = x[1];
        z[2] = x[2];
    }

    private static void addTo(long[] x, long[] z) {
        z[0] = z[0] ^ x[0];
        z[1] = z[1] ^ x[1];
        z[2] = z[2] ^ x[2];
    }

    public static long[] fromBigInteger(BigInteger x) {
        return Nat.fromBigInteger64(131, x);
    }

    public static void halfTrace(long[] x, long[] z) {
        long[] tt = Nat.create64(5);
        Nat192.copy64(x, z);
        for (int i = 1; i < 131; i += 2) {
            implSquare(z, tt);
            reduce(tt, z);
            implSquare(z, tt);
            reduce(tt, z);
            addTo(x, z);
        }
    }

    public static void invert(long[] x, long[] z) {
        if (Nat192.isZero64(x)) {
            throw new IllegalStateException();
        }
        long[] t0 = Nat192.create64();
        long[] t1 = Nat192.create64();
        square(x, t0);
        multiply(t0, x, t0);
        squareN(t0, 2, t1);
        multiply(t1, t0, t1);
        squareN(t1, 4, t0);
        multiply(t0, t1, t0);
        squareN(t0, 8, t1);
        multiply(t1, t0, t1);
        squareN(t1, 16, t0);
        multiply(t0, t1, t0);
        squareN(t0, 32, t1);
        multiply(t1, t0, t1);
        square(t1, t1);
        multiply(t1, x, t1);
        squareN(t1, 65, t0);
        multiply(t0, t1, t0);
        square(t0, z);
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
        long x4 = xx[4];
        long x32 = x3 ^ (x4 >>> 59);
        long x22 = (x2 ^ ((((x4 >>> 3) ^ (x4 >>> 1)) ^ x4) ^ (x4 << 5))) ^ (x32 >>> 59);
        long t = x22 >>> 3;
        z[0] = ((((x0 ^ ((x32 << 61) ^ (x32 << 63))) ^ t) ^ (t << 2)) ^ (t << 3)) ^ (t << 8);
        z[1] = (t >>> 56) ^ ((x1 ^ ((x4 << 61) ^ (x4 << 63))) ^ ((((x32 >>> 3) ^ (x32 >>> 1)) ^ x32) ^ (x32 << 5)));
        z[2] = M03 & x22;
    }

    public static void reduce61(long[] z, int zOff) {
        long z2 = z[zOff + 2];
        long t = z2 >>> 3;
        z[zOff] = z[zOff] ^ ((((t << 2) ^ t) ^ (t << 3)) ^ (t << 8));
        int i = zOff + 1;
        z[i] = z[i] ^ (t >>> 56);
        z[zOff + 2] = M03 & z2;
    }

    public static void sqrt(long[] x, long[] z) {
        long[] odd = Nat192.create64();
        long u0 = Interleave.unshuffle(x[0]);
        long u1 = Interleave.unshuffle(x[1]);
        long e0 = (4294967295L & u0) | (u1 << 32);
        odd[0] = (u0 >>> 32) | (-4294967296L & u1);
        long u02 = Interleave.unshuffle(x[2]);
        odd[1] = u02 >>> 32;
        multiply(odd, ROOT_Z, z);
        z[0] = z[0] ^ e0;
        z[1] = z[1] ^ (u02 & 4294967295L);
    }

    public static void square(long[] x, long[] z) {
        long[] tt = Nat.create64(5);
        implSquare(x, tt);
        reduce(tt, z);
    }

    public static void squareAddToExt(long[] x, long[] zz) {
        long[] tt = Nat.create64(5);
        implSquare(x, tt);
        addExt(zz, tt, zz);
    }

    public static void squareN(long[] x, int n, long[] z) {
        long[] tt = Nat.create64(5);
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
        return ((int) ((x[0] ^ (x[1] >>> 59)) ^ (x[2] >>> 1))) & 1;
    }

    protected static void implCompactExt(long[] zz) {
        long z0 = zz[0];
        long z1 = zz[1];
        long z2 = zz[2];
        long z3 = zz[3];
        long z4 = zz[4];
        long z5 = zz[5];
        zz[0] = (z1 << 44) ^ z0;
        zz[1] = (z1 >>> 20) ^ (z2 << 24);
        zz[2] = ((z2 >>> 40) ^ (z3 << 4)) ^ (z4 << 48);
        zz[3] = ((z3 >>> 60) ^ (z5 << 28)) ^ (z4 >>> 16);
        zz[4] = z5 >>> 36;
        zz[5] = 0;
    }

    protected static void implMultiply(long[] x, long[] y, long[] zz) {
        long f0 = x[0];
        long f1 = x[1];
        long f2 = ((f1 >>> 24) ^ (x[2] << 40)) & M44;
        long f12 = ((f0 >>> 44) ^ (f1 << 20)) & M44;
        long f02 = f0 & M44;
        long g0 = y[0];
        long g1 = y[1];
        long g2 = ((g1 >>> 24) ^ (y[2] << 40)) & M44;
        long g12 = ((g0 >>> 44) ^ (g1 << 20)) & M44;
        long g02 = g0 & M44;
        long[] H = new long[10];
        implMulw(zz, f02, g02, H, 0);
        implMulw(zz, f2, g2, H, 2);
        long t0 = (f02 ^ f12) ^ f2;
        long t1 = (g02 ^ g12) ^ g2;
        implMulw(zz, t0, t1, H, 4);
        long t2 = (f12 << 1) ^ (f2 << 2);
        long t3 = (g12 << 1) ^ (g2 << 2);
        implMulw(zz, f02 ^ t2, g02 ^ t3, H, 6);
        implMulw(zz, t0 ^ t2, t1 ^ t3, H, 8);
        long t4 = H[6] ^ H[8];
        long t5 = H[7] ^ H[9];
        long v0 = (t4 << 1) ^ H[6];
        long v1 = ((t5 << 1) ^ t4) ^ H[7];
        long u0 = H[0];
        long u1 = (H[1] ^ H[0]) ^ H[4];
        long u2 = H[1] ^ H[5];
        long w0 = ((u0 ^ v0) ^ (H[2] << 4)) ^ (H[2] << 1);
        long w1 = (((u1 ^ v1) ^ (H[3] << 4)) ^ (H[3] << 1)) ^ (w0 >>> 44);
        long w02 = w0 & M44;
        long w2 = (u2 ^ t5) ^ (w1 >>> 44);
        long w12 = w1 & M44;
        long w03 = (w02 >>> 1) ^ ((1 & w12) << 43);
        long w04 = w03 ^ (w03 << 1);
        long w05 = w04 ^ (w04 << 2);
        long w06 = w05 ^ (w05 << 4);
        long w07 = w06 ^ (w06 << 8);
        long w08 = w07 ^ (w07 << 16);
        long w09 = (w08 ^ (w08 << 32)) & M44;
        long w13 = ((w12 >>> 1) ^ ((1 & w2) << 43)) ^ (w09 >>> 43);
        long w14 = w13 ^ (w13 << 1);
        long w15 = w14 ^ (w14 << 2);
        long w16 = w15 ^ (w15 << 4);
        long w17 = w16 ^ (w16 << 8);
        long w18 = w17 ^ (w17 << 16);
        long w19 = (w18 ^ (w18 << 32)) & M44;
        long w22 = (w2 >>> 1) ^ (w19 >>> 43);
        long w23 = w22 ^ (w22 << 1);
        long w24 = w23 ^ (w23 << 2);
        long w25 = w24 ^ (w24 << 4);
        long w26 = w25 ^ (w25 << 8);
        long w27 = w26 ^ (w26 << 16);
        long w28 = w27 ^ (w27 << 32);
        zz[0] = u0;
        zz[1] = (u1 ^ w09) ^ H[2];
        zz[2] = ((u2 ^ w19) ^ w09) ^ H[3];
        zz[3] = w28 ^ w19;
        zz[4] = H[2] ^ w28;
        zz[5] = H[3];
        implCompactExt(zz);
    }

    protected static void implMulw(long[] u, long x, long y, long[] z, int zOff) {
        u[1] = y;
        u[2] = u[1] << 1;
        u[3] = u[2] ^ y;
        u[4] = u[2] << 1;
        u[5] = u[4] ^ y;
        u[6] = u[3] << 1;
        u[7] = u[6] ^ y;
        int j = (int) x;
        long h = 0;
        long l = (((u[j & 7] ^ (u[(j >>> 3) & 7] << 3)) ^ (u[(j >>> 6) & 7] << 6)) ^ (u[(j >>> 9) & 7] << 9)) ^ (u[(j >>> 12) & 7] << 12);
        int k = 30;
        do {
            int j2 = (int) (x >>> k);
            long g = (((u[j2 & 7] ^ (u[(j2 >>> 3) & 7] << 3)) ^ (u[(j2 >>> 6) & 7] << 6)) ^ (u[(j2 >>> 9) & 7] << 9)) ^ (u[(j2 >>> 12) & 7] << 12);
            l ^= g << k;
            h ^= g >>> (-k);
            k -= 15;
        } while (k > 0);
        z[zOff] = M44 & l;
        z[zOff + 1] = (l >>> 44) ^ (h << 20);
    }

    protected static void implSquare(long[] x, long[] zz) {
        Interleave.expand64To128(x, 0, 2, zz, 0);
        zz[4] = ((long) Interleave.expand8to16((int) x[2])) & 4294967295L;
    }
}
