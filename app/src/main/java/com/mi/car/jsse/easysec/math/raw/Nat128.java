package com.mi.car.jsse.easysec.math.raw;

import com.mi.car.jsse.easysec.util.Pack;
import java.math.BigInteger;

public abstract class Nat128 {
    private static final long M = 4294967295L;

    public static int add(int[] x, int[] y, int[] z) {
        long c = 0 + (((long) x[0]) & M) + (((long) y[0]) & M);
        z[0] = (int) c;
        long c2 = (c >>> 32) + (((long) x[1]) & M) + (((long) y[1]) & M);
        z[1] = (int) c2;
        long c3 = (c2 >>> 32) + (((long) x[2]) & M) + (((long) y[2]) & M);
        z[2] = (int) c3;
        long c4 = (c3 >>> 32) + (((long) x[3]) & M) + (((long) y[3]) & M);
        z[3] = (int) c4;
        return (int) (c4 >>> 32);
    }

    public static int addBothTo(int[] x, int[] y, int[] z) {
        long c = 0 + (((long) x[0]) & M) + (((long) y[0]) & M) + (((long) z[0]) & M);
        z[0] = (int) c;
        long c2 = (c >>> 32) + (((long) x[1]) & M) + (((long) y[1]) & M) + (((long) z[1]) & M);
        z[1] = (int) c2;
        long c3 = (c2 >>> 32) + (((long) x[2]) & M) + (((long) y[2]) & M) + (((long) z[2]) & M);
        z[2] = (int) c3;
        long c4 = (c3 >>> 32) + (((long) x[3]) & M) + (((long) y[3]) & M) + (((long) z[3]) & M);
        z[3] = (int) c4;
        return (int) (c4 >>> 32);
    }

    public static int addTo(int[] x, int[] z) {
        long c = 0 + (((long) x[0]) & M) + (((long) z[0]) & M);
        z[0] = (int) c;
        long c2 = (c >>> 32) + (((long) x[1]) & M) + (((long) z[1]) & M);
        z[1] = (int) c2;
        long c3 = (c2 >>> 32) + (((long) x[2]) & M) + (((long) z[2]) & M);
        z[2] = (int) c3;
        long c4 = (c3 >>> 32) + (((long) x[3]) & M) + (((long) z[3]) & M);
        z[3] = (int) c4;
        return (int) (c4 >>> 32);
    }

    public static int addTo(int[] x, int xOff, int[] z, int zOff, int cIn) {
        long c = (((long) cIn) & M) + (((long) x[xOff + 0]) & M) + (((long) z[zOff + 0]) & M);
        z[zOff + 0] = (int) c;
        long c2 = (c >>> 32) + (((long) x[xOff + 1]) & M) + (((long) z[zOff + 1]) & M);
        z[zOff + 1] = (int) c2;
        long c3 = (c2 >>> 32) + (((long) x[xOff + 2]) & M) + (((long) z[zOff + 2]) & M);
        z[zOff + 2] = (int) c3;
        long c4 = (c3 >>> 32) + (((long) x[xOff + 3]) & M) + (((long) z[zOff + 3]) & M);
        z[zOff + 3] = (int) c4;
        return (int) (c4 >>> 32);
    }

    public static int addToEachOther(int[] u, int uOff, int[] v, int vOff) {
        long c = 0 + (((long) u[uOff + 0]) & M) + (((long) v[vOff + 0]) & M);
        u[uOff + 0] = (int) c;
        v[vOff + 0] = (int) c;
        long c2 = (c >>> 32) + (((long) u[uOff + 1]) & M) + (((long) v[vOff + 1]) & M);
        u[uOff + 1] = (int) c2;
        v[vOff + 1] = (int) c2;
        long c3 = (c2 >>> 32) + (((long) u[uOff + 2]) & M) + (((long) v[vOff + 2]) & M);
        u[uOff + 2] = (int) c3;
        v[vOff + 2] = (int) c3;
        long c4 = (c3 >>> 32) + (((long) u[uOff + 3]) & M) + (((long) v[vOff + 3]) & M);
        u[uOff + 3] = (int) c4;
        v[vOff + 3] = (int) c4;
        return (int) (c4 >>> 32);
    }

    public static void copy(int[] x, int[] z) {
        z[0] = x[0];
        z[1] = x[1];
        z[2] = x[2];
        z[3] = x[3];
    }

    public static void copy(int[] x, int xOff, int[] z, int zOff) {
        z[zOff + 0] = x[xOff + 0];
        z[zOff + 1] = x[xOff + 1];
        z[zOff + 2] = x[xOff + 2];
        z[zOff + 3] = x[xOff + 3];
    }

    public static void copy64(long[] x, long[] z) {
        z[0] = x[0];
        z[1] = x[1];
    }

    public static void copy64(long[] x, int xOff, long[] z, int zOff) {
        z[zOff + 0] = x[xOff + 0];
        z[zOff + 1] = x[xOff + 1];
    }

    public static int[] create() {
        return new int[4];
    }

    public static long[] create64() {
        return new long[2];
    }

    public static int[] createExt() {
        return new int[8];
    }

    public static long[] createExt64() {
        return new long[4];
    }

    public static boolean diff(int[] x, int xOff, int[] y, int yOff, int[] z, int zOff) {
        boolean pos = gte(x, xOff, y, yOff);
        if (pos) {
            sub(x, xOff, y, yOff, z, zOff);
        } else {
            sub(y, yOff, x, xOff, z, zOff);
        }
        return pos;
    }

    public static boolean eq(int[] x, int[] y) {
        for (int i = 3; i >= 0; i--) {
            if (x[i] != y[i]) {
                return false;
            }
        }
        return true;
    }

    public static boolean eq64(long[] x, long[] y) {
        for (int i = 1; i >= 0; i--) {
            if (x[i] != y[i]) {
                return false;
            }
        }
        return true;
    }

    public static int[] fromBigInteger(BigInteger x) {
        if (x.signum() < 0 || x.bitLength() > 128) {
            throw new IllegalArgumentException();
        }
        int[] z = create();
        for (int i = 0; i < 4; i++) {
            z[i] = x.intValue();
            x = x.shiftRight(32);
        }
        return z;
    }

    public static long[] fromBigInteger64(BigInteger x) {
        if (x.signum() < 0 || x.bitLength() > 128) {
            throw new IllegalArgumentException();
        }
        long[] z = create64();
        for (int i = 0; i < 2; i++) {
            z[i] = x.longValue();
            x = x.shiftRight(64);
        }
        return z;
    }

    public static int getBit(int[] x, int bit) {
        if (bit == 0) {
            return x[0] & 1;
        }
        int w = bit >> 5;
        if (w < 0 || w >= 4) {
            return 0;
        }
        return (x[w] >>> (bit & 31)) & 1;
    }

    public static boolean gte(int[] x, int[] y) {
        for (int i = 3; i >= 0; i--) {
            int x_i = x[i] ^ Integer.MIN_VALUE;
            int y_i = y[i] ^ Integer.MIN_VALUE;
            if (x_i < y_i) {
                return false;
            }
            if (x_i > y_i) {
                return true;
            }
        }
        return true;
    }

    public static boolean gte(int[] x, int xOff, int[] y, int yOff) {
        for (int i = 3; i >= 0; i--) {
            int x_i = x[xOff + i] ^ Integer.MIN_VALUE;
            int y_i = y[yOff + i] ^ Integer.MIN_VALUE;
            if (x_i < y_i) {
                return false;
            }
            if (x_i > y_i) {
                return true;
            }
        }
        return true;
    }

    public static boolean isOne(int[] x) {
        if (x[0] != 1) {
            return false;
        }
        for (int i = 1; i < 4; i++) {
            if (x[i] != 0) {
                return false;
            }
        }
        return true;
    }

    public static boolean isOne64(long[] x) {
        if (x[0] != 1) {
            return false;
        }
        for (int i = 1; i < 2; i++) {
            if (x[i] != 0) {
                return false;
            }
        }
        return true;
    }

    public static boolean isZero(int[] x) {
        for (int i = 0; i < 4; i++) {
            if (x[i] != 0) {
                return false;
            }
        }
        return true;
    }

    public static boolean isZero64(long[] x) {
        for (int i = 0; i < 2; i++) {
            if (x[i] != 0) {
                return false;
            }
        }
        return true;
    }

    public static void mul(int[] x, int[] y, int[] zz) {
        long y_0 = ((long) y[0]) & M;
        long y_1 = ((long) y[1]) & M;
        long y_2 = ((long) y[2]) & M;
        long y_3 = ((long) y[3]) & M;
        long x_0 = ((long) x[0]) & M;
        long c = 0 + (x_0 * y_0);
        zz[0] = (int) c;
        long c2 = (c >>> 32) + (x_0 * y_1);
        zz[1] = (int) c2;
        long c3 = (c2 >>> 32) + (x_0 * y_2);
        zz[2] = (int) c3;
        long c4 = (c3 >>> 32) + (x_0 * y_3);
        zz[3] = (int) c4;
        zz[4] = (int) (c4 >>> 32);
        for (int i = 1; i < 4; i++) {
            long x_i = ((long) x[i]) & M;
            long c5 = 0 + (x_i * y_0) + (((long) zz[i + 0]) & M);
            zz[i + 0] = (int) c5;
            long c6 = (c5 >>> 32) + (x_i * y_1) + (((long) zz[i + 1]) & M);
            zz[i + 1] = (int) c6;
            long c7 = (c6 >>> 32) + (x_i * y_2) + (((long) zz[i + 2]) & M);
            zz[i + 2] = (int) c7;
            long c8 = (c7 >>> 32) + (x_i * y_3) + (((long) zz[i + 3]) & M);
            zz[i + 3] = (int) c8;
            zz[i + 4] = (int) (c8 >>> 32);
        }
    }

    public static void mul(int[] x, int xOff, int[] y, int yOff, int[] zz, int zzOff) {
        long y_0 = ((long) y[yOff + 0]) & M;
        long y_1 = ((long) y[yOff + 1]) & M;
        long y_2 = ((long) y[yOff + 2]) & M;
        long y_3 = ((long) y[yOff + 3]) & M;
        long x_0 = ((long) x[xOff + 0]) & M;
        long c = 0 + (x_0 * y_0);
        zz[zzOff + 0] = (int) c;
        long c2 = (c >>> 32) + (x_0 * y_1);
        zz[zzOff + 1] = (int) c2;
        long c3 = (c2 >>> 32) + (x_0 * y_2);
        zz[zzOff + 2] = (int) c3;
        long c4 = (c3 >>> 32) + (x_0 * y_3);
        zz[zzOff + 3] = (int) c4;
        zz[zzOff + 4] = (int) (c4 >>> 32);
        for (int i = 1; i < 4; i++) {
            zzOff++;
            long x_i = ((long) x[xOff + i]) & M;
            long c5 = 0 + (x_i * y_0) + (((long) zz[zzOff + 0]) & M);
            zz[zzOff + 0] = (int) c5;
            long c6 = (c5 >>> 32) + (x_i * y_1) + (((long) zz[zzOff + 1]) & M);
            zz[zzOff + 1] = (int) c6;
            long c7 = (c6 >>> 32) + (x_i * y_2) + (((long) zz[zzOff + 2]) & M);
            zz[zzOff + 2] = (int) c7;
            long c8 = (c7 >>> 32) + (x_i * y_3) + (((long) zz[zzOff + 3]) & M);
            zz[zzOff + 3] = (int) c8;
            zz[zzOff + 4] = (int) (c8 >>> 32);
        }
    }

    public static int mulAddTo(int[] x, int[] y, int[] zz) {
        long y_0 = ((long) y[0]) & M;
        long y_1 = ((long) y[1]) & M;
        long y_2 = ((long) y[2]) & M;
        long y_3 = ((long) y[3]) & M;
        long zc = 0;
        for (int i = 0; i < 4; i++) {
            long x_i = ((long) x[i]) & M;
            long c = 0 + (x_i * y_0) + (((long) zz[i + 0]) & M);
            zz[i + 0] = (int) c;
            long c2 = (c >>> 32) + (x_i * y_1) + (((long) zz[i + 1]) & M);
            zz[i + 1] = (int) c2;
            long c3 = (c2 >>> 32) + (x_i * y_2) + (((long) zz[i + 2]) & M);
            zz[i + 2] = (int) c3;
            long c4 = (c3 >>> 32) + (x_i * y_3) + (((long) zz[i + 3]) & M);
            zz[i + 3] = (int) c4;
            long zc2 = zc + (((long) zz[i + 4]) & M) + (c4 >>> 32);
            zz[i + 4] = (int) zc2;
            zc = zc2 >>> 32;
        }
        return (int) zc;
    }

    public static int mulAddTo(int[] x, int xOff, int[] y, int yOff, int[] zz, int zzOff) {
        long y_0 = ((long) y[yOff + 0]) & M;
        long y_1 = ((long) y[yOff + 1]) & M;
        long y_2 = ((long) y[yOff + 2]) & M;
        long y_3 = ((long) y[yOff + 3]) & M;
        long zc = 0;
        for (int i = 0; i < 4; i++) {
            long x_i = ((long) x[xOff + i]) & M;
            long c = 0 + (x_i * y_0) + (((long) zz[zzOff + 0]) & M);
            zz[zzOff + 0] = (int) c;
            long c2 = (c >>> 32) + (x_i * y_1) + (((long) zz[zzOff + 1]) & M);
            zz[zzOff + 1] = (int) c2;
            long c3 = (c2 >>> 32) + (x_i * y_2) + (((long) zz[zzOff + 2]) & M);
            zz[zzOff + 2] = (int) c3;
            long c4 = (c3 >>> 32) + (x_i * y_3) + (((long) zz[zzOff + 3]) & M);
            zz[zzOff + 3] = (int) c4;
            long zc2 = zc + (((long) zz[zzOff + 4]) & M) + (c4 >>> 32);
            zz[zzOff + 4] = (int) zc2;
            zc = zc2 >>> 32;
            zzOff++;
        }
        return (int) zc;
    }

    public static long mul33Add(int w, int[] x, int xOff, int[] y, int yOff, int[] z, int zOff) {
        long wVal = ((long) w) & M;
        long x0 = ((long) x[xOff + 0]) & M;
        long c = 0 + (wVal * x0) + (((long) y[yOff + 0]) & M);
        z[zOff + 0] = (int) c;
        long x1 = ((long) x[xOff + 1]) & M;
        long c2 = (c >>> 32) + (wVal * x1) + x0 + (((long) y[yOff + 1]) & M);
        z[zOff + 1] = (int) c2;
        long x2 = ((long) x[xOff + 2]) & M;
        long c3 = (c2 >>> 32) + (wVal * x2) + x1 + (((long) y[yOff + 2]) & M);
        z[zOff + 2] = (int) c3;
        long x3 = ((long) x[xOff + 3]) & M;
        long c4 = (c3 >>> 32) + (wVal * x3) + x2 + (((long) y[yOff + 3]) & M);
        z[zOff + 3] = (int) c4;
        return (c4 >>> 32) + x3;
    }

    public static int mulWordAddExt(int x, int[] yy, int yyOff, int[] zz, int zzOff) {
        long xVal = ((long) x) & M;
        long c = 0 + ((((long) yy[yyOff + 0]) & M) * xVal) + (((long) zz[zzOff + 0]) & M);
        zz[zzOff + 0] = (int) c;
        long c2 = (c >>> 32) + ((((long) yy[yyOff + 1]) & M) * xVal) + (((long) zz[zzOff + 1]) & M);
        zz[zzOff + 1] = (int) c2;
        long c3 = (c2 >>> 32) + ((((long) yy[yyOff + 2]) & M) * xVal) + (((long) zz[zzOff + 2]) & M);
        zz[zzOff + 2] = (int) c3;
        long c4 = (c3 >>> 32) + ((((long) yy[yyOff + 3]) & M) * xVal) + (((long) zz[zzOff + 3]) & M);
        zz[zzOff + 3] = (int) c4;
        return (int) (c4 >>> 32);
    }

    public static int mul33DWordAdd(int x, long y, int[] z, int zOff) {
        long xVal = ((long) x) & M;
        long y00 = y & M;
        long c = 0 + (xVal * y00) + (((long) z[zOff + 0]) & M);
        z[zOff + 0] = (int) c;
        long y01 = y >>> 32;
        long c2 = (c >>> 32) + (xVal * y01) + y00 + (((long) z[zOff + 1]) & M);
        z[zOff + 1] = (int) c2;
        long c3 = (c2 >>> 32) + (((long) z[zOff + 2]) & M) + y01;
        z[zOff + 2] = (int) c3;
        long c4 = (c3 >>> 32) + (((long) z[zOff + 3]) & M);
        z[zOff + 3] = (int) c4;
        return (int) (c4 >>> 32);
    }

    public static int mul33WordAdd(int x, int y, int[] z, int zOff) {
        long xVal = ((long) x) & M;
        long yVal = ((long) y) & M;
        long c = 0 + (yVal * xVal) + (((long) z[zOff + 0]) & M);
        z[zOff + 0] = (int) c;
        long c2 = (c >>> 32) + (((long) z[zOff + 1]) & M) + yVal;
        z[zOff + 1] = (int) c2;
        long c3 = (c2 >>> 32) + (((long) z[zOff + 2]) & M);
        z[zOff + 2] = (int) c3;
        if ((c3 >>> 32) == 0) {
            return 0;
        }
        return Nat.incAt(4, z, zOff, 3);
    }

    public static int mulWordDwordAdd(int x, long y, int[] z, int zOff) {
        long xVal = ((long) x) & M;
        long c = 0 + ((y & M) * xVal) + (((long) z[zOff + 0]) & M);
        z[zOff + 0] = (int) c;
        long c2 = (c >>> 32) + ((y >>> 32) * xVal) + (((long) z[zOff + 1]) & M);
        z[zOff + 1] = (int) c2;
        long c3 = (c2 >>> 32) + (((long) z[zOff + 2]) & M);
        z[zOff + 2] = (int) c3;
        if ((c3 >>> 32) == 0) {
            return 0;
        }
        return Nat.incAt(4, z, zOff, 3);
    }

    public static int mulWordsAdd(int x, int y, int[] z, int zOff) {
        long c = 0 + ((((long) y) & M) * (((long) x) & M)) + (((long) z[zOff + 0]) & M);
        z[zOff + 0] = (int) c;
        long c2 = (c >>> 32) + (((long) z[zOff + 1]) & M);
        z[zOff + 1] = (int) c2;
        if ((c2 >>> 32) == 0) {
            return 0;
        }
        return Nat.incAt(4, z, zOff, 2);
    }

    public static int mulWord(int x, int[] y, int[] z, int zOff) {
        long c = 0;
        long xVal = ((long) x) & M;
        int i = 0;
        do {
            long c2 = c + ((((long) y[i]) & M) * xVal);
            z[zOff + i] = (int) c2;
            c = c2 >>> 32;
            i++;
        } while (i < 4);
        return (int) c;
    }

    public static void square(int[] x, int[] zz) {
        long x_0 = ((long) x[0]) & M;
        int c = 0;
        int i = 3;
        int j = 8;
        while (true) {
            int i2 = i - 1;
            long xVal = ((long) x[i]) & M;
            long p = xVal * xVal;
            int j2 = j - 1;
            zz[j2] = (c << 31) | ((int) (p >>> 33));
            j = j2 - 1;
            zz[j] = (int) (p >>> 1);
            c = (int) p;
            if (i2 <= 0) {
                long p2 = x_0 * x_0;
                long zz_1 = (((long) (c << 31)) & M) | (p2 >>> 33);
                zz[0] = (int) p2;
                long x_1 = ((long) x[1]) & M;
                long zz_2 = ((long) zz[2]) & M;
                long zz_12 = zz_1 + (x_1 * x_0);
                int w = (int) zz_12;
                zz[1] = (w << 1) | (((int) (p2 >>> 32)) & 1);
                int c2 = w >>> 31;
                long x_2 = ((long) x[2]) & M;
                long zz_3 = ((long) zz[3]) & M;
                long zz_4 = ((long) zz[4]) & M;
                long zz_22 = zz_2 + (zz_12 >>> 32) + (x_2 * x_0);
                int w2 = (int) zz_22;
                zz[2] = (w2 << 1) | c2;
                int c3 = w2 >>> 31;
                long zz_32 = zz_3 + (zz_22 >>> 32) + (x_2 * x_1);
                long zz_42 = zz_4 + (zz_32 >>> 32);
                long zz_33 = zz_32 & M;
                long x_3 = ((long) x[3]) & M;
                long zz_5 = (((long) zz[5]) & M) + (zz_42 >>> 32);
                long zz_43 = zz_42 & M;
                long zz_6 = (((long) zz[6]) & M) + (zz_5 >>> 32);
                long zz_52 = zz_5 & M;
                long zz_34 = zz_33 + (x_3 * x_0);
                int w3 = (int) zz_34;
                zz[3] = (w3 << 1) | c3;
                int c4 = w3 >>> 31;
                long zz_44 = zz_43 + (zz_34 >>> 32) + (x_3 * x_1);
                long zz_53 = zz_52 + (zz_44 >>> 32) + (x_3 * x_2);
                long zz_62 = zz_6 + (zz_53 >>> 32);
                long zz_54 = zz_53 & M;
                int w4 = (int) zz_44;
                zz[4] = (w4 << 1) | c4;
                int c5 = w4 >>> 31;
                int w5 = (int) zz_54;
                zz[5] = (w5 << 1) | c5;
                int c6 = w5 >>> 31;
                int w6 = (int) zz_62;
                zz[6] = (w6 << 1) | c6;
                zz[7] = ((zz[7] + ((int) (zz_62 >>> 32))) << 1) | (w6 >>> 31);
                return;
            }
            i = i2;
        }
    }

    public static void square(int[] x, int xOff, int[] zz, int zzOff) {
        long x_0 = ((long) x[xOff + 0]) & M;
        int c = 0;
        int i = 3;
        int j = 8;
        while (true) {
            int i2 = i - 1;
            long xVal = ((long) x[xOff + i]) & M;
            long p = xVal * xVal;
            int j2 = j - 1;
            zz[zzOff + j2] = (c << 31) | ((int) (p >>> 33));
            j = j2 - 1;
            zz[zzOff + j] = (int) (p >>> 1);
            c = (int) p;
            if (i2 <= 0) {
                long p2 = x_0 * x_0;
                long zz_1 = (((long) (c << 31)) & M) | (p2 >>> 33);
                zz[zzOff + 0] = (int) p2;
                long x_1 = ((long) x[xOff + 1]) & M;
                long zz_2 = ((long) zz[zzOff + 2]) & M;
                long zz_12 = zz_1 + (x_1 * x_0);
                int w = (int) zz_12;
                zz[zzOff + 1] = (w << 1) | (((int) (p2 >>> 32)) & 1);
                int c2 = w >>> 31;
                long x_2 = ((long) x[xOff + 2]) & M;
                long zz_3 = ((long) zz[zzOff + 3]) & M;
                long zz_4 = ((long) zz[zzOff + 4]) & M;
                long zz_22 = zz_2 + (zz_12 >>> 32) + (x_2 * x_0);
                int w2 = (int) zz_22;
                zz[zzOff + 2] = (w2 << 1) | c2;
                int c3 = w2 >>> 31;
                long zz_32 = zz_3 + (zz_22 >>> 32) + (x_2 * x_1);
                long zz_42 = zz_4 + (zz_32 >>> 32);
                long zz_33 = zz_32 & M;
                long x_3 = ((long) x[xOff + 3]) & M;
                long zz_5 = (((long) zz[zzOff + 5]) & M) + (zz_42 >>> 32);
                long zz_43 = zz_42 & M;
                long zz_6 = (((long) zz[zzOff + 6]) & M) + (zz_5 >>> 32);
                long zz_52 = zz_5 & M;
                long zz_34 = zz_33 + (x_3 * x_0);
                int w3 = (int) zz_34;
                zz[zzOff + 3] = (w3 << 1) | c3;
                int c4 = w3 >>> 31;
                long zz_44 = zz_43 + (zz_34 >>> 32) + (x_3 * x_1);
                long zz_53 = zz_52 + (zz_44 >>> 32) + (x_3 * x_2);
                long zz_62 = zz_6 + (zz_53 >>> 32);
                int w4 = (int) zz_44;
                zz[zzOff + 4] = (w4 << 1) | c4;
                int c5 = w4 >>> 31;
                int w5 = (int) zz_53;
                zz[zzOff + 5] = (w5 << 1) | c5;
                int c6 = w5 >>> 31;
                int w6 = (int) zz_62;
                zz[zzOff + 6] = (w6 << 1) | c6;
                zz[zzOff + 7] = ((zz[zzOff + 7] + ((int) (zz_62 >>> 32))) << 1) | (w6 >>> 31);
                return;
            }
            i = i2;
        }
    }

    public static int sub(int[] x, int[] y, int[] z) {
        long c = 0 + ((((long) x[0]) & M) - (((long) y[0]) & M));
        z[0] = (int) c;
        long c2 = (c >> 32) + ((((long) x[1]) & M) - (((long) y[1]) & M));
        z[1] = (int) c2;
        long c3 = (c2 >> 32) + ((((long) x[2]) & M) - (((long) y[2]) & M));
        z[2] = (int) c3;
        long c4 = (c3 >> 32) + ((((long) x[3]) & M) - (((long) y[3]) & M));
        z[3] = (int) c4;
        return (int) (c4 >> 32);
    }

    public static int sub(int[] x, int xOff, int[] y, int yOff, int[] z, int zOff) {
        long c = 0 + ((((long) x[xOff + 0]) & M) - (((long) y[yOff + 0]) & M));
        z[zOff + 0] = (int) c;
        long c2 = (c >> 32) + ((((long) x[xOff + 1]) & M) - (((long) y[yOff + 1]) & M));
        z[zOff + 1] = (int) c2;
        long c3 = (c2 >> 32) + ((((long) x[xOff + 2]) & M) - (((long) y[yOff + 2]) & M));
        z[zOff + 2] = (int) c3;
        long c4 = (c3 >> 32) + ((((long) x[xOff + 3]) & M) - (((long) y[yOff + 3]) & M));
        z[zOff + 3] = (int) c4;
        return (int) (c4 >> 32);
    }

    public static int subBothFrom(int[] x, int[] y, int[] z) {
        long c = 0 + (((((long) z[0]) & M) - (((long) x[0]) & M)) - (((long) y[0]) & M));
        z[0] = (int) c;
        long c2 = (c >> 32) + (((((long) z[1]) & M) - (((long) x[1]) & M)) - (((long) y[1]) & M));
        z[1] = (int) c2;
        long c3 = (c2 >> 32) + (((((long) z[2]) & M) - (((long) x[2]) & M)) - (((long) y[2]) & M));
        z[2] = (int) c3;
        long c4 = (c3 >> 32) + (((((long) z[3]) & M) - (((long) x[3]) & M)) - (((long) y[3]) & M));
        z[3] = (int) c4;
        return (int) (c4 >> 32);
    }

    public static int subFrom(int[] x, int[] z) {
        long c = 0 + ((((long) z[0]) & M) - (((long) x[0]) & M));
        z[0] = (int) c;
        long c2 = (c >> 32) + ((((long) z[1]) & M) - (((long) x[1]) & M));
        z[1] = (int) c2;
        long c3 = (c2 >> 32) + ((((long) z[2]) & M) - (((long) x[2]) & M));
        z[2] = (int) c3;
        long c4 = (c3 >> 32) + ((((long) z[3]) & M) - (((long) x[3]) & M));
        z[3] = (int) c4;
        return (int) (c4 >> 32);
    }

    public static int subFrom(int[] x, int xOff, int[] z, int zOff) {
        long c = 0 + ((((long) z[zOff + 0]) & M) - (((long) x[xOff + 0]) & M));
        z[zOff + 0] = (int) c;
        long c2 = (c >> 32) + ((((long) z[zOff + 1]) & M) - (((long) x[xOff + 1]) & M));
        z[zOff + 1] = (int) c2;
        long c3 = (c2 >> 32) + ((((long) z[zOff + 2]) & M) - (((long) x[xOff + 2]) & M));
        z[zOff + 2] = (int) c3;
        long c4 = (c3 >> 32) + ((((long) z[zOff + 3]) & M) - (((long) x[xOff + 3]) & M));
        z[zOff + 3] = (int) c4;
        return (int) (c4 >> 32);
    }

    public static BigInteger toBigInteger(int[] x) {
        byte[] bs = new byte[16];
        for (int i = 0; i < 4; i++) {
            int x_i = x[i];
            if (x_i != 0) {
                Pack.intToBigEndian(x_i, bs, (3 - i) << 2);
            }
        }
        return new BigInteger(1, bs);
    }

    public static BigInteger toBigInteger64(long[] x) {
        byte[] bs = new byte[16];
        for (int i = 0; i < 2; i++) {
            long x_i = x[i];
            if (x_i != 0) {
                Pack.longToBigEndian(x_i, bs, (1 - i) << 3);
            }
        }
        return new BigInteger(1, bs);
    }

    public static void zero(int[] z) {
        z[0] = 0;
        z[1] = 0;
        z[2] = 0;
        z[3] = 0;
    }
}
