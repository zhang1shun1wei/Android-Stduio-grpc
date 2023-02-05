package com.mi.car.jsse.easysec.math.ec.custom.sec;

import com.mi.car.jsse.easysec.math.raw.Interleave;
import com.mi.car.jsse.easysec.math.raw.Nat;
import com.mi.car.jsse.easysec.math.raw.Nat576;
import java.math.BigInteger;

public class SecT571Field {
    private static final long M59 = 576460752303423487L;
    private static final long[] ROOT_Z = {3161836309350906777L, -7642453882179322845L, -3821226941089661423L, 7312758566309945096L, -556661012383879292L, 8945041530681231562L, -4750851271514160027L, 6847946401097695794L, 541669439031730457L};

    public static void add(long[] x, long[] y, long[] z) {
        for (int i = 0; i < 9; i++) {
            z[i] = x[i] ^ y[i];
        }
    }

    private static void add(long[] x, int xOff, long[] y, int yOff, long[] z, int zOff) {
        for (int i = 0; i < 9; i++) {
            z[zOff + i] = x[xOff + i] ^ y[yOff + i];
        }
    }

    public static void addBothTo(long[] x, long[] y, long[] z) {
        for (int i = 0; i < 9; i++) {
            z[i] = z[i] ^ (x[i] ^ y[i]);
        }
    }

    private static void addBothTo(long[] x, int xOff, long[] y, int yOff, long[] z, int zOff) {
        for (int i = 0; i < 9; i++) {
            int i2 = zOff + i;
            z[i2] = z[i2] ^ (x[xOff + i] ^ y[yOff + i]);
        }
    }

    public static void addExt(long[] xx, long[] yy, long[] zz) {
        for (int i = 0; i < 18; i++) {
            zz[i] = xx[i] ^ yy[i];
        }
    }

    public static void addOne(long[] x, long[] z) {
        z[0] = x[0] ^ 1;
        for (int i = 1; i < 9; i++) {
            z[i] = x[i];
        }
    }

    private static void addTo(long[] x, long[] z) {
        for (int i = 0; i < 9; i++) {
            z[i] = z[i] ^ x[i];
        }
    }

    public static long[] fromBigInteger(BigInteger x) {
        return Nat.fromBigInteger64(571, x);
    }

    public static void halfTrace(long[] x, long[] z) {
        long[] tt = Nat576.createExt64();
        Nat576.copy64(x, z);
        for (int i = 1; i < 571; i += 2) {
            implSquare(z, tt);
            reduce(tt, z);
            implSquare(z, tt);
            reduce(tt, z);
            addTo(x, z);
        }
    }

    public static void invert(long[] x, long[] z) {
        if (Nat576.isZero64(x)) {
            throw new IllegalStateException();
        }
        long[] t0 = Nat576.create64();
        long[] t1 = Nat576.create64();
        long[] t2 = Nat576.create64();
        square(x, t2);
        square(t2, t0);
        square(t0, t1);
        multiply(t0, t1, t0);
        squareN(t0, 2, t1);
        multiply(t0, t1, t0);
        multiply(t0, t2, t0);
        squareN(t0, 5, t1);
        multiply(t0, t1, t0);
        squareN(t1, 5, t1);
        multiply(t0, t1, t0);
        squareN(t0, 15, t1);
        multiply(t0, t1, t2);
        squareN(t2, 30, t0);
        squareN(t0, 30, t1);
        multiply(t0, t1, t0);
        squareN(t0, 60, t1);
        multiply(t0, t1, t0);
        squareN(t1, 60, t1);
        multiply(t0, t1, t0);
        squareN(t0, 180, t1);
        multiply(t0, t1, t0);
        squareN(t1, 180, t1);
        multiply(t0, t1, t0);
        multiply(t0, t2, z);
    }

    public static void multiply(long[] x, long[] y, long[] z) {
        long[] tt = Nat576.createExt64();
        implMultiply(x, y, tt);
        reduce(tt, z);
    }

    public static void multiplyAddToExt(long[] x, long[] y, long[] zz) {
        long[] tt = Nat576.createExt64();
        implMultiply(x, y, tt);
        addExt(zz, tt, zz);
    }

    public static void multiplyPrecomp(long[] x, long[] precomp, long[] z) {
        long[] tt = Nat576.createExt64();
        implMultiplyPrecomp(x, precomp, tt);
        reduce(tt, z);
    }

    public static void multiplyPrecompAddToExt(long[] x, long[] precomp, long[] zz) {
        long[] tt = Nat576.createExt64();
        implMultiplyPrecomp(x, precomp, tt);
        addExt(zz, tt, zz);
    }

    public static long[] precompMultiplicand(long[] x) {
        long[] t = new long[288];
        System.arraycopy(x, 0, t, 9, 9);
        int tOff = 0;
        for (int i = 7; i > 0; i--) {
            tOff += 18;
            Nat.shiftUpBit64(9, t, tOff >>> 1, 0, t, tOff);
            reduce5(t, tOff);
            add(t, 9, t, tOff, t, tOff + 9);
        }
        Nat.shiftUpBits64(144, t, 0, 4, 0, t, 144);
        return t;
    }

    public static void reduce(long[] xx, long[] z) {
        long xx09 = xx[9];
        long u = xx[17];
        long xx092 = ((((u >>> 59) ^ xx09) ^ (u >>> 57)) ^ (u >>> 54)) ^ (u >>> 49);
        long v = (((xx[8] ^ (u << 5)) ^ (u << 7)) ^ (u << 10)) ^ (u << 15);
        for (int i = 16; i >= 10; i--) {
            long u2 = xx[i];
            z[i - 8] = ((((u2 >>> 59) ^ v) ^ (u2 >>> 57)) ^ (u2 >>> 54)) ^ (u2 >>> 49);
            v = (((xx[i - 9] ^ (u2 << 5)) ^ (u2 << 7)) ^ (u2 << 10)) ^ (u2 << 15);
        }
        z[1] = ((((xx092 >>> 59) ^ v) ^ (xx092 >>> 57)) ^ (xx092 >>> 54)) ^ (xx092 >>> 49);
        long x08 = z[8];
        long t = x08 >>> 59;
        z[0] = (((((((xx[0] ^ (xx092 << 5)) ^ (xx092 << 7)) ^ (xx092 << 10)) ^ (xx092 << 15)) ^ t) ^ (t << 2)) ^ (t << 5)) ^ (t << 10);
        z[8] = M59 & x08;
    }

    public static void reduce5(long[] z, int zOff) {
        long z8 = z[zOff + 8];
        long t = z8 >>> 59;
        z[zOff] = z[zOff] ^ ((((t << 2) ^ t) ^ (t << 5)) ^ (t << 10));
        z[zOff + 8] = M59 & z8;
    }

    public static void sqrt(long[] x, long[] z) {
        long[] evn = Nat576.create64();
        long[] odd = Nat576.create64();
        int pos = 0;
        for (int i = 0; i < 4; i++) {
            int pos2 = pos + 1;
            long u0 = Interleave.unshuffle(x[pos]);
            pos = pos2 + 1;
            long u1 = Interleave.unshuffle(x[pos2]);
            evn[i] = (4294967295L & u0) | (u1 << 32);
            odd[i] = (u0 >>> 32) | (-4294967296L & u1);
        }
        long u02 = Interleave.unshuffle(x[pos]);
        evn[4] = 4294967295L & u02;
        odd[4] = u02 >>> 32;
        multiply(odd, ROOT_Z, z);
        add(z, evn, z);
    }

    public static void square(long[] x, long[] z) {
        long[] tt = Nat576.createExt64();
        implSquare(x, tt);
        reduce(tt, z);
    }

    public static void squareAddToExt(long[] x, long[] zz) {
        long[] tt = Nat576.createExt64();
        implSquare(x, tt);
        addExt(zz, tt, zz);
    }

    public static void squareN(long[] x, int n, long[] z) {
        long[] tt = Nat576.createExt64();
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
        return ((int) ((x[0] ^ (x[8] >>> 49)) ^ (x[8] >>> 57))) & 1;
    }

    protected static void implMultiply(long[] x, long[] y, long[] zz) {
        long[] u = new long[16];
        for (int i = 0; i < 9; i++) {
            implMulwAcc(u, x[i], y[i], zz, i << 1);
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
        long v17 = v16 ^ zz[13];
        long v08 = v07 ^ zz[14];
        zz[7] = v08 ^ v17;
        long v18 = v17 ^ zz[15];
        long v09 = v08 ^ zz[16];
        zz[8] = v09 ^ v18;
        long w = v09 ^ (v18 ^ zz[17]);
        zz[9] = zz[0] ^ w;
        zz[10] = zz[1] ^ w;
        zz[11] = zz[2] ^ w;
        zz[12] = zz[3] ^ w;
        zz[13] = zz[4] ^ w;
        zz[14] = zz[5] ^ w;
        zz[15] = zz[6] ^ w;
        zz[16] = zz[7] ^ w;
        zz[17] = zz[8] ^ w;
        implMulwAcc(u, x[0] ^ x[1], y[0] ^ y[1], zz, 1);
        implMulwAcc(u, x[0] ^ x[2], y[0] ^ y[2], zz, 2);
        implMulwAcc(u, x[0] ^ x[3], y[0] ^ y[3], zz, 3);
        implMulwAcc(u, x[1] ^ x[2], y[1] ^ y[2], zz, 3);
        implMulwAcc(u, x[0] ^ x[4], y[0] ^ y[4], zz, 4);
        implMulwAcc(u, x[1] ^ x[3], y[1] ^ y[3], zz, 4);
        implMulwAcc(u, x[0] ^ x[5], y[0] ^ y[5], zz, 5);
        implMulwAcc(u, x[1] ^ x[4], y[1] ^ y[4], zz, 5);
        implMulwAcc(u, x[2] ^ x[3], y[2] ^ y[3], zz, 5);
        implMulwAcc(u, x[0] ^ x[6], y[0] ^ y[6], zz, 6);
        implMulwAcc(u, x[1] ^ x[5], y[1] ^ y[5], zz, 6);
        implMulwAcc(u, x[2] ^ x[4], y[2] ^ y[4], zz, 6);
        implMulwAcc(u, x[0] ^ x[7], y[0] ^ y[7], zz, 7);
        implMulwAcc(u, x[1] ^ x[6], y[1] ^ y[6], zz, 7);
        implMulwAcc(u, x[2] ^ x[5], y[2] ^ y[5], zz, 7);
        implMulwAcc(u, x[3] ^ x[4], y[3] ^ y[4], zz, 7);
        implMulwAcc(u, x[0] ^ x[8], y[0] ^ y[8], zz, 8);
        implMulwAcc(u, x[1] ^ x[7], y[1] ^ y[7], zz, 8);
        implMulwAcc(u, x[2] ^ x[6], y[2] ^ y[6], zz, 8);
        implMulwAcc(u, x[3] ^ x[5], y[3] ^ y[5], zz, 8);
        implMulwAcc(u, x[1] ^ x[8], y[1] ^ y[8], zz, 9);
        implMulwAcc(u, x[2] ^ x[7], y[2] ^ y[7], zz, 9);
        implMulwAcc(u, x[3] ^ x[6], y[3] ^ y[6], zz, 9);
        implMulwAcc(u, x[4] ^ x[5], y[4] ^ y[5], zz, 9);
        implMulwAcc(u, x[2] ^ x[8], y[2] ^ y[8], zz, 10);
        implMulwAcc(u, x[3] ^ x[7], y[3] ^ y[7], zz, 10);
        implMulwAcc(u, x[4] ^ x[6], y[4] ^ y[6], zz, 10);
        implMulwAcc(u, x[3] ^ x[8], y[3] ^ y[8], zz, 11);
        implMulwAcc(u, x[4] ^ x[7], y[4] ^ y[7], zz, 11);
        implMulwAcc(u, x[5] ^ x[6], y[5] ^ y[6], zz, 11);
        implMulwAcc(u, x[4] ^ x[8], y[4] ^ y[8], zz, 12);
        implMulwAcc(u, x[5] ^ x[7], y[5] ^ y[7], zz, 12);
        implMulwAcc(u, x[5] ^ x[8], y[5] ^ y[8], zz, 13);
        implMulwAcc(u, x[6] ^ x[7], y[6] ^ y[7], zz, 13);
        implMulwAcc(u, x[6] ^ x[8], y[6] ^ y[8], zz, 14);
        implMulwAcc(u, x[7] ^ x[8], y[7] ^ y[8], zz, 15);
    }

    protected static void implMultiplyPrecomp(long[] x, long[] precomp, long[] zz) {
        for (int k = 56; k >= 0; k -= 8) {
            for (int j = 1; j < 9; j += 2) {
                int aVal = (int) (x[j] >>> k);
                addBothTo(precomp, (aVal & 15) * 9, precomp, (((aVal >>> 4) & 15) + 16) * 9, zz, j - 1);
            }
            Nat.shiftUpBits64(16, zz, 0, 8, 0);
        }
        for (int k2 = 56; k2 >= 0; k2 -= 8) {
            for (int j2 = 0; j2 < 9; j2 += 2) {
                int aVal2 = (int) (x[j2] >>> k2);
                addBothTo(precomp, (aVal2 & 15) * 9, precomp, (((aVal2 >>> 4) & 15) + 16) * 9, zz, j2);
            }
            if (k2 > 0) {
                Nat.shiftUpBits64(18, zz, 0, 8, 0);
            }
        }
    }

    protected static void implMulwAcc(long[] u, long x, long y, long[] z, int zOff) {
        u[1] = y;
        for (int i = 2; i < 16; i += 2) {
            u[i] = u[i >>> 1] << 1;
            u[i + 1] = u[i] ^ y;
        }
        int j = (int) x;
        long h = 0;
        long l = u[j & 15] ^ (u[(j >>> 4) & 15] << 4);
        int k = 56;
        do {
            int j2 = (int) (x >>> k);
            long g = u[j2 & 15] ^ (u[(j2 >>> 4) & 15] << 4);
            l ^= g << k;
            h ^= g >>> (-k);
            k -= 8;
        } while (k > 0);
        for (int p = 0; p < 7; p++) {
            x = (-72340172838076674L & x) >>> 1;
            h ^= ((y << p) >> 63) & x;
        }
        z[zOff] = z[zOff] ^ l;
        int i2 = zOff + 1;
        z[i2] = z[i2] ^ h;
    }

    protected static void implSquare(long[] x, long[] zz) {
        Interleave.expand64To128(x, 0, 9, zz, 0);
    }
}
