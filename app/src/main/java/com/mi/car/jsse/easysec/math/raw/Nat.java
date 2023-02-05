package com.mi.car.jsse.easysec.math.raw;

import com.mi.car.jsse.easysec.util.Pack;
import java.math.BigInteger;

public abstract class Nat {
    private static final long M = 4294967295L;

    public static int add(int len, int[] x, int[] y, int[] z) {
        long c = 0;
        for (int i = 0; i < len; i++) {
            long c2 = c + (((long) x[i]) & M) + (((long) y[i]) & M);
            z[i] = (int) c2;
            c = c2 >>> 32;
        }
        return (int) c;
    }

    public static int add33At(int len, int x, int[] z, int zPos) {
        long c = (((long) z[zPos + 0]) & M) + (((long) x) & M);
        z[zPos + 0] = (int) c;
        long c2 = (c >>> 32) + (((long) z[zPos + 1]) & M) + 1;
        z[zPos + 1] = (int) c2;
        if ((c2 >>> 32) == 0) {
            return 0;
        }
        return incAt(len, z, zPos + 2);
    }

    public static int add33At(int len, int x, int[] z, int zOff, int zPos) {
        long c = (((long) z[zOff + zPos]) & M) + (((long) x) & M);
        z[zOff + zPos] = (int) c;
        long c2 = (c >>> 32) + (((long) z[zOff + zPos + 1]) & M) + 1;
        z[zOff + zPos + 1] = (int) c2;
        if ((c2 >>> 32) == 0) {
            return 0;
        }
        return incAt(len, z, zOff, zPos + 2);
    }

    public static int add33To(int len, int x, int[] z) {
        long c = (((long) z[0]) & M) + (((long) x) & M);
        z[0] = (int) c;
        long c2 = (c >>> 32) + (((long) z[1]) & M) + 1;
        z[1] = (int) c2;
        if ((c2 >>> 32) == 0) {
            return 0;
        }
        return incAt(len, z, 2);
    }

    public static int add33To(int len, int x, int[] z, int zOff) {
        long c = (((long) z[zOff + 0]) & M) + (((long) x) & M);
        z[zOff + 0] = (int) c;
        long c2 = (c >>> 32) + (((long) z[zOff + 1]) & M) + 1;
        z[zOff + 1] = (int) c2;
        if ((c2 >>> 32) == 0) {
            return 0;
        }
        return incAt(len, z, zOff, 2);
    }

    public static int addBothTo(int len, int[] x, int[] y, int[] z) {
        long c = 0;
        for (int i = 0; i < len; i++) {
            long c2 = c + (((long) x[i]) & M) + (((long) y[i]) & M) + (((long) z[i]) & M);
            z[i] = (int) c2;
            c = c2 >>> 32;
        }
        return (int) c;
    }

    public static int addBothTo(int len, int[] x, int xOff, int[] y, int yOff, int[] z, int zOff) {
        long c = 0;
        for (int i = 0; i < len; i++) {
            long c2 = c + (((long) x[xOff + i]) & M) + (((long) y[yOff + i]) & M) + (((long) z[zOff + i]) & M);
            z[zOff + i] = (int) c2;
            c = c2 >>> 32;
        }
        return (int) c;
    }

    public static int addDWordAt(int len, long x, int[] z, int zPos) {
        long c = (((long) z[zPos + 0]) & M) + (x & M);
        z[zPos + 0] = (int) c;
        long c2 = (c >>> 32) + (((long) z[zPos + 1]) & M) + (x >>> 32);
        z[zPos + 1] = (int) c2;
        if ((c2 >>> 32) == 0) {
            return 0;
        }
        return incAt(len, z, zPos + 2);
    }

    public static int addDWordAt(int len, long x, int[] z, int zOff, int zPos) {
        long c = (((long) z[zOff + zPos]) & M) + (x & M);
        z[zOff + zPos] = (int) c;
        long c2 = (c >>> 32) + (((long) z[zOff + zPos + 1]) & M) + (x >>> 32);
        z[zOff + zPos + 1] = (int) c2;
        if ((c2 >>> 32) == 0) {
            return 0;
        }
        return incAt(len, z, zOff, zPos + 2);
    }

    public static int addDWordTo(int len, long x, int[] z) {
        long c = (((long) z[0]) & M) + (x & M);
        z[0] = (int) c;
        long c2 = (c >>> 32) + (((long) z[1]) & M) + (x >>> 32);
        z[1] = (int) c2;
        if ((c2 >>> 32) == 0) {
            return 0;
        }
        return incAt(len, z, 2);
    }

    public static int addDWordTo(int len, long x, int[] z, int zOff) {
        long c = (((long) z[zOff + 0]) & M) + (x & M);
        z[zOff + 0] = (int) c;
        long c2 = (c >>> 32) + (((long) z[zOff + 1]) & M) + (x >>> 32);
        z[zOff + 1] = (int) c2;
        if ((c2 >>> 32) == 0) {
            return 0;
        }
        return incAt(len, z, zOff, 2);
    }

    public static int addTo(int len, int[] x, int[] z) {
        long c = 0;
        for (int i = 0; i < len; i++) {
            long c2 = c + (((long) x[i]) & M) + (((long) z[i]) & M);
            z[i] = (int) c2;
            c = c2 >>> 32;
        }
        return (int) c;
    }

    public static int addTo(int len, int[] x, int xOff, int[] z, int zOff) {
        long c = 0;
        for (int i = 0; i < len; i++) {
            long c2 = c + (((long) x[xOff + i]) & M) + (((long) z[zOff + i]) & M);
            z[zOff + i] = (int) c2;
            c = c2 >>> 32;
        }
        return (int) c;
    }

    public static int addTo(int len, int[] x, int xOff, int[] z, int zOff, int cIn) {
        long c = ((long) cIn) & M;
        for (int i = 0; i < len; i++) {
            long c2 = c + (((long) x[xOff + i]) & M) + (((long) z[zOff + i]) & M);
            z[zOff + i] = (int) c2;
            c = c2 >>> 32;
        }
        return (int) c;
    }

    public static int addToEachOther(int len, int[] u, int uOff, int[] v, int vOff) {
        long c = 0;
        for (int i = 0; i < len; i++) {
            long c2 = c + (((long) u[uOff + i]) & M) + (((long) v[vOff + i]) & M);
            u[uOff + i] = (int) c2;
            v[vOff + i] = (int) c2;
            c = c2 >>> 32;
        }
        return (int) c;
    }

    public static int addWordAt(int len, int x, int[] z, int zPos) {
        long c = (((long) x) & M) + (((long) z[zPos]) & M);
        z[zPos] = (int) c;
        if ((c >>> 32) == 0) {
            return 0;
        }
        return incAt(len, z, zPos + 1);
    }

    public static int addWordAt(int len, int x, int[] z, int zOff, int zPos) {
        long c = (((long) x) & M) + (((long) z[zOff + zPos]) & M);
        z[zOff + zPos] = (int) c;
        if ((c >>> 32) == 0) {
            return 0;
        }
        return incAt(len, z, zOff, zPos + 1);
    }

    public static int addWordTo(int len, int x, int[] z) {
        long c = (((long) x) & M) + (((long) z[0]) & M);
        z[0] = (int) c;
        if ((c >>> 32) == 0) {
            return 0;
        }
        return incAt(len, z, 1);
    }

    public static int addWordTo(int len, int x, int[] z, int zOff) {
        long c = (((long) x) & M) + (((long) z[zOff]) & M);
        z[zOff] = (int) c;
        if ((c >>> 32) == 0) {
            return 0;
        }
        return incAt(len, z, zOff, 1);
    }

    public static int cadd(int len, int mask, int[] x, int[] y, int[] z) {
        long MASK = ((long) (-(mask & 1))) & M;
        long c = 0;
        for (int i = 0; i < len; i++) {
            long c2 = c + (((long) x[i]) & M) + (((long) y[i]) & MASK);
            z[i] = (int) c2;
            c = c2 >>> 32;
        }
        return (int) c;
    }

    public static void cmov(int len, int mask, int[] x, int xOff, int[] z, int zOff) {
        int mask2 = -(mask & 1);
        for (int i = 0; i < len; i++) {
            int z_i = z[zOff + i];
            z[zOff + i] = z_i ^ ((z_i ^ x[xOff + i]) & mask2);
        }
    }

    public static int compare(int len, int[] x, int[] y) {
        for (int i = len - 1; i >= 0; i--) {
            int x_i = x[i] ^ Integer.MIN_VALUE;
            int y_i = y[i] ^ Integer.MIN_VALUE;
            if (x_i < y_i) {
                return -1;
            }
            if (x_i > y_i) {
                return 1;
            }
        }
        return 0;
    }

    public static int compare(int len, int[] x, int xOff, int[] y, int yOff) {
        for (int i = len - 1; i >= 0; i--) {
            int x_i = x[xOff + i] ^ Integer.MIN_VALUE;
            int y_i = y[yOff + i] ^ Integer.MIN_VALUE;
            if (x_i < y_i) {
                return -1;
            }
            if (x_i > y_i) {
                return 1;
            }
        }
        return 0;
    }

    public static int[] copy(int len, int[] x) {
        int[] z = new int[len];
        System.arraycopy(x, 0, z, 0, len);
        return z;
    }

    public static void copy(int len, int[] x, int[] z) {
        System.arraycopy(x, 0, z, 0, len);
    }

    public static void copy(int len, int[] x, int xOff, int[] z, int zOff) {
        System.arraycopy(x, xOff, z, zOff, len);
    }

    public static long[] copy64(int len, long[] x) {
        long[] z = new long[len];
        System.arraycopy(x, 0, z, 0, len);
        return z;
    }

    public static void copy64(int len, long[] x, long[] z) {
        System.arraycopy(x, 0, z, 0, len);
    }

    public static void copy64(int len, long[] x, int xOff, long[] z, int zOff) {
        System.arraycopy(x, xOff, z, zOff, len);
    }

    public static int[] create(int len) {
        return new int[len];
    }

    public static long[] create64(int len) {
        return new long[len];
    }

    public static int csub(int len, int mask, int[] x, int[] y, int[] z) {
        long MASK = ((long) (-(mask & 1))) & M;
        long c = 0;
        for (int i = 0; i < len; i++) {
            long c2 = c + ((((long) x[i]) & M) - (((long) y[i]) & MASK));
            z[i] = (int) c2;
            c = c2 >> 32;
        }
        return (int) c;
    }

    public static int csub(int len, int mask, int[] x, int xOff, int[] y, int yOff, int[] z, int zOff) {
        long MASK = ((long) (-(mask & 1))) & M;
        long c = 0;
        for (int i = 0; i < len; i++) {
            long c2 = c + ((((long) x[xOff + i]) & M) - (((long) y[yOff + i]) & MASK));
            z[zOff + i] = (int) c2;
            c = c2 >> 32;
        }
        return (int) c;
    }

    public static int dec(int len, int[] z) {
        for (int i = 0; i < len; i++) {
            int i2 = z[i] - 1;
            z[i] = i2;
            if (i2 != -1) {
                return 0;
            }
        }
        return -1;
    }

    public static int dec(int len, int[] x, int[] z) {
        int i = 0;
        while (i < len) {
            int c = x[i] - 1;
            z[i] = c;
            i++;
            if (c != -1) {
                while (i < len) {
                    z[i] = x[i];
                    i++;
                }
                return 0;
            }
        }
        return -1;
    }

    public static int decAt(int len, int[] z, int zPos) {
        for (int i = zPos; i < len; i++) {
            int i2 = z[i] - 1;
            z[i] = i2;
            if (i2 != -1) {
                return 0;
            }
        }
        return -1;
    }

    public static int decAt(int len, int[] z, int zOff, int zPos) {
        for (int i = zPos; i < len; i++) {
            int i2 = zOff + i;
            int i3 = z[i2] - 1;
            z[i2] = i3;
            if (i3 != -1) {
                return 0;
            }
        }
        return -1;
    }

    public static boolean diff(int len, int[] x, int xOff, int[] y, int yOff, int[] z, int zOff) {
        boolean pos = gte(len, x, xOff, y, yOff);
        if (pos) {
            sub(len, x, xOff, y, yOff, z, zOff);
        } else {
            sub(len, y, yOff, x, xOff, z, zOff);
        }
        return pos;
    }

    public static boolean eq(int len, int[] x, int[] y) {
        for (int i = len - 1; i >= 0; i--) {
            if (x[i] != y[i]) {
                return false;
            }
        }
        return true;
    }

    public static int equalTo(int len, int[] x, int y) {
        int d = x[0] ^ y;
        for (int i = 1; i < len; i++) {
            d |= x[i];
        }
        return (((d >>> 1) | (d & 1)) - 1) >> 31;
    }

    public static int equalTo(int len, int[] x, int xOff, int y) {
        int d = x[xOff] ^ y;
        for (int i = 1; i < len; i++) {
            d |= x[xOff + i];
        }
        return (((d >>> 1) | (d & 1)) - 1) >> 31;
    }

    public static int equalTo(int len, int[] x, int[] y) {
        int d = 0;
        for (int i = 0; i < len; i++) {
            d |= x[i] ^ y[i];
        }
        return (((d >>> 1) | (d & 1)) - 1) >> 31;
    }

    public static int equalTo(int len, int[] x, int xOff, int[] y, int yOff) {
        int d = 0;
        for (int i = 0; i < len; i++) {
            d |= x[xOff + i] ^ y[yOff + i];
        }
        return (((d >>> 1) | (d & 1)) - 1) >> 31;
    }

    public static int equalToZero(int len, int[] x) {
        int d = 0;
        for (int i = 0; i < len; i++) {
            d |= x[i];
        }
        return (((d >>> 1) | (d & 1)) - 1) >> 31;
    }

    public static int equalToZero(int len, int[] x, int xOff) {
        int d = 0;
        for (int i = 0; i < len; i++) {
            d |= x[xOff + i];
        }
        return (((d >>> 1) | (d & 1)) - 1) >> 31;
    }

    public static int[] fromBigInteger(int bits, BigInteger x) {
        if (x.signum() < 0 || x.bitLength() > bits) {
            throw new IllegalArgumentException();
        }
        int len = (bits + 31) >> 5;
        int[] z = create(len);
        for (int i = 0; i < len; i++) {
            z[i] = x.intValue();
            x = x.shiftRight(32);
        }
        return z;
    }

    public static long[] fromBigInteger64(int bits, BigInteger x) {
        if (x.signum() < 0 || x.bitLength() > bits) {
            throw new IllegalArgumentException();
        }
        int len = (bits + 63) >> 6;
        long[] z = create64(len);
        for (int i = 0; i < len; i++) {
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
        if (w < 0 || w >= x.length) {
            return 0;
        }
        return (x[w] >>> (bit & 31)) & 1;
    }

    public static boolean gte(int len, int[] x, int[] y) {
        for (int i = len - 1; i >= 0; i--) {
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

    public static boolean gte(int len, int[] x, int xOff, int[] y, int yOff) {
        for (int i = len - 1; i >= 0; i--) {
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

    public static int inc(int len, int[] z) {
        for (int i = 0; i < len; i++) {
            int i2 = z[i] + 1;
            z[i] = i2;
            if (i2 != 0) {
                return 0;
            }
        }
        return 1;
    }

    public static int inc(int len, int[] x, int[] z) {
        int i = 0;
        while (i < len) {
            int c = x[i] + 1;
            z[i] = c;
            i++;
            if (c != 0) {
                while (i < len) {
                    z[i] = x[i];
                    i++;
                }
                return 0;
            }
        }
        return 1;
    }

    public static int incAt(int len, int[] z, int zPos) {
        for (int i = zPos; i < len; i++) {
            int i2 = z[i] + 1;
            z[i] = i2;
            if (i2 != 0) {
                return 0;
            }
        }
        return 1;
    }

    public static int incAt(int len, int[] z, int zOff, int zPos) {
        for (int i = zPos; i < len; i++) {
            int i2 = zOff + i;
            int i3 = z[i2] + 1;
            z[i2] = i3;
            if (i3 != 0) {
                return 0;
            }
        }
        return 1;
    }

    public static boolean isOne(int len, int[] x) {
        if (x[0] != 1) {
            return false;
        }
        for (int i = 1; i < len; i++) {
            if (x[i] != 0) {
                return false;
            }
        }
        return true;
    }

    public static boolean isZero(int len, int[] x) {
        for (int i = 0; i < len; i++) {
            if (x[i] != 0) {
                return false;
            }
        }
        return true;
    }

    public static int lessThan(int len, int[] x, int[] y) {
        long c = 0;
        for (int i = 0; i < len; i++) {
            c = (c + ((((long) x[i]) & M) - (((long) y[i]) & M))) >> 32;
        }
        return (int) c;
    }

    public static int lessThan(int len, int[] x, int xOff, int[] y, int yOff) {
        long c = 0;
        for (int i = 0; i < len; i++) {
            c = (c + ((((long) x[xOff + i]) & M) - (((long) y[yOff + i]) & M))) >> 32;
        }
        return (int) c;
    }

    public static void mul(int len, int[] x, int[] y, int[] zz) {
        zz[len] = mulWord(len, x[0], y, zz);
        for (int i = 1; i < len; i++) {
            zz[i + len] = mulWordAddTo(len, x[i], y, 0, zz, i);
        }
    }

    public static void mul(int len, int[] x, int xOff, int[] y, int yOff, int[] zz, int zzOff) {
        zz[zzOff + len] = mulWord(len, x[xOff], y, yOff, zz, zzOff);
        for (int i = 1; i < len; i++) {
            zz[zzOff + i + len] = mulWordAddTo(len, x[xOff + i], y, yOff, zz, zzOff + i);
        }
    }

    public static void mul(int[] x, int xOff, int xLen, int[] y, int yOff, int yLen, int[] zz, int zzOff) {
        zz[zzOff + yLen] = mulWord(yLen, x[xOff], y, yOff, zz, zzOff);
        for (int i = 1; i < xLen; i++) {
            zz[zzOff + i + yLen] = mulWordAddTo(yLen, x[xOff + i], y, yOff, zz, zzOff + i);
        }
    }

    public static int mulAddTo(int len, int[] x, int[] y, int[] zz) {
        long zc = 0;
        for (int i = 0; i < len; i++) {
            long zc2 = zc + (((long) mulWordAddTo(len, x[i], y, 0, zz, i)) & M) + (((long) zz[i + len]) & M);
            zz[i + len] = (int) zc2;
            zc = zc2 >>> 32;
        }
        return (int) zc;
    }

    public static int mulAddTo(int len, int[] x, int xOff, int[] y, int yOff, int[] zz, int zzOff) {
        long zc = 0;
        for (int i = 0; i < len; i++) {
            long zc2 = zc + (((long) mulWordAddTo(len, x[xOff + i], y, yOff, zz, zzOff)) & M) + (((long) zz[zzOff + len]) & M);
            zz[zzOff + len] = (int) zc2;
            zc = zc2 >>> 32;
            zzOff++;
        }
        return (int) zc;
    }

    public static int mul31BothAdd(int len, int a, int[] x, int b, int[] y, int[] z, int zOff) {
        long c = 0;
        long aVal = ((long) a) & M;
        long bVal = ((long) b) & M;
        int i = 0;
        do {
            long c2 = c + ((((long) x[i]) & M) * aVal) + ((((long) y[i]) & M) * bVal) + (((long) z[zOff + i]) & M);
            z[zOff + i] = (int) c2;
            c = c2 >>> 32;
            i++;
        } while (i < len);
        return (int) c;
    }

    public static int mulWord(int len, int x, int[] y, int[] z) {
        long c = 0;
        long xVal = ((long) x) & M;
        int i = 0;
        do {
            long c2 = c + ((((long) y[i]) & M) * xVal);
            z[i] = (int) c2;
            c = c2 >>> 32;
            i++;
        } while (i < len);
        return (int) c;
    }

    public static int mulWord(int len, int x, int[] y, int yOff, int[] z, int zOff) {
        long c = 0;
        long xVal = ((long) x) & M;
        int i = 0;
        do {
            long c2 = c + ((((long) y[yOff + i]) & M) * xVal);
            z[zOff + i] = (int) c2;
            c = c2 >>> 32;
            i++;
        } while (i < len);
        return (int) c;
    }

    public static int mulWordAddTo(int len, int x, int[] y, int yOff, int[] z, int zOff) {
        long c = 0;
        long xVal = ((long) x) & M;
        int i = 0;
        do {
            long c2 = c + ((((long) y[yOff + i]) & M) * xVal) + (((long) z[zOff + i]) & M);
            z[zOff + i] = (int) c2;
            c = c2 >>> 32;
            i++;
        } while (i < len);
        return (int) c;
    }

    public static int mulWordDwordAddAt(int len, int x, long y, int[] z, int zPos) {
        long xVal = ((long) x) & M;
        long c = 0 + ((M & y) * xVal) + (((long) z[zPos + 0]) & M);
        z[zPos + 0] = (int) c;
        long c2 = (c >>> 32) + ((y >>> 32) * xVal) + (((long) z[zPos + 1]) & M);
        z[zPos + 1] = (int) c2;
        long c3 = (c2 >>> 32) + (((long) z[zPos + 2]) & M);
        z[zPos + 2] = (int) c3;
        if ((c3 >>> 32) == 0) {
            return 0;
        }
        return incAt(len, z, zPos + 3);
    }

    public static int shiftDownBit(int len, int[] z, int c) {
        int i = len;
        while (true) {
            i--;
            if (i < 0) {
                return c << 31;
            }
            int next = z[i];
            z[i] = (next >>> 1) | (c << 31);
            c = next;
        }
    }

    public static int shiftDownBit(int len, int[] z, int zOff, int c) {
        int i = len;
        while (true) {
            i--;
            if (i < 0) {
                return c << 31;
            }
            int next = z[zOff + i];
            z[zOff + i] = (next >>> 1) | (c << 31);
            c = next;
        }
    }

    public static int shiftDownBit(int len, int[] x, int c, int[] z) {
        int i = len;
        while (true) {
            i--;
            if (i < 0) {
                return c << 31;
            }
            int next = x[i];
            z[i] = (next >>> 1) | (c << 31);
            c = next;
        }
    }

    public static int shiftDownBit(int len, int[] x, int xOff, int c, int[] z, int zOff) {
        int i = len;
        while (true) {
            i--;
            if (i < 0) {
                return c << 31;
            }
            int next = x[xOff + i];
            z[zOff + i] = (next >>> 1) | (c << 31);
            c = next;
        }
    }

    public static int shiftDownBits(int len, int[] z, int bits, int c) {
        int i = len;
        while (true) {
            i--;
            if (i < 0) {
                return c << (-bits);
            }
            int next = z[i];
            z[i] = (next >>> bits) | (c << (-bits));
            c = next;
        }
    }

    public static int shiftDownBits(int len, int[] z, int zOff, int bits, int c) {
        int i = len;
        while (true) {
            i--;
            if (i < 0) {
                return c << (-bits);
            }
            int next = z[zOff + i];
            z[zOff + i] = (next >>> bits) | (c << (-bits));
            c = next;
        }
    }

    public static int shiftDownBits(int len, int[] x, int bits, int c, int[] z) {
        int i = len;
        while (true) {
            i--;
            if (i < 0) {
                return c << (-bits);
            }
            int next = x[i];
            z[i] = (next >>> bits) | (c << (-bits));
            c = next;
        }
    }

    public static int shiftDownBits(int len, int[] x, int xOff, int bits, int c, int[] z, int zOff) {
        int i = len;
        while (true) {
            i--;
            if (i < 0) {
                return c << (-bits);
            }
            int next = x[xOff + i];
            z[zOff + i] = (next >>> bits) | (c << (-bits));
            c = next;
        }
    }

    public static int shiftDownWord(int len, int[] z, int c) {
        int i = len;
        while (true) {
            i--;
            if (i < 0) {
                return c;
            }
            int next = z[i];
            z[i] = c;
            c = next;
        }
    }

    public static int shiftUpBit(int len, int[] z, int c) {
        for (int i = 0; i < len; i++) {
            int next = z[i];
            z[i] = (next << 1) | (c >>> 31);
            c = next;
        }
        return c >>> 31;
    }

    public static int shiftUpBit(int len, int[] z, int zOff, int c) {
        for (int i = 0; i < len; i++) {
            int next = z[zOff + i];
            z[zOff + i] = (next << 1) | (c >>> 31);
            c = next;
        }
        return c >>> 31;
    }

    public static int shiftUpBit(int len, int[] x, int c, int[] z) {
        for (int i = 0; i < len; i++) {
            int next = x[i];
            z[i] = (next << 1) | (c >>> 31);
            c = next;
        }
        return c >>> 31;
    }

    public static int shiftUpBit(int len, int[] x, int xOff, int c, int[] z, int zOff) {
        for (int i = 0; i < len; i++) {
            int next = x[xOff + i];
            z[zOff + i] = (next << 1) | (c >>> 31);
            c = next;
        }
        return c >>> 31;
    }

    public static long shiftUpBit64(int len, long[] x, int xOff, long c, long[] z, int zOff) {
        for (int i = 0; i < len; i++) {
            long next = x[xOff + i];
            z[zOff + i] = (next << 1) | (c >>> 63);
            c = next;
        }
        return c >>> 63;
    }

    public static int shiftUpBits(int len, int[] z, int bits, int c) {
        for (int i = 0; i < len; i++) {
            int next = z[i];
            z[i] = (next << bits) | (c >>> (-bits));
            c = next;
        }
        return c >>> (-bits);
    }

    public static int shiftUpBits(int len, int[] z, int zOff, int bits, int c) {
        for (int i = 0; i < len; i++) {
            int next = z[zOff + i];
            z[zOff + i] = (next << bits) | (c >>> (-bits));
            c = next;
        }
        return c >>> (-bits);
    }

    public static long shiftUpBits64(int len, long[] z, int zOff, int bits, long c) {
        for (int i = 0; i < len; i++) {
            long next = z[zOff + i];
            z[zOff + i] = (next << bits) | (c >>> (-bits));
            c = next;
        }
        return c >>> (-bits);
    }

    public static int shiftUpBits(int len, int[] x, int bits, int c, int[] z) {
        for (int i = 0; i < len; i++) {
            int next = x[i];
            z[i] = (next << bits) | (c >>> (-bits));
            c = next;
        }
        return c >>> (-bits);
    }

    public static int shiftUpBits(int len, int[] x, int xOff, int bits, int c, int[] z, int zOff) {
        for (int i = 0; i < len; i++) {
            int next = x[xOff + i];
            z[zOff + i] = (next << bits) | (c >>> (-bits));
            c = next;
        }
        return c >>> (-bits);
    }

    public static long shiftUpBits64(int len, long[] x, int xOff, int bits, long c, long[] z, int zOff) {
        for (int i = 0; i < len; i++) {
            long next = x[xOff + i];
            z[zOff + i] = (next << bits) | (c >>> (-bits));
            c = next;
        }
        return c >>> (-bits);
    }

    public static void square(int len, int[] x, int[] zz) {
        int extLen = len << 1;
        int c = 0;
        int j = len;
        int k = extLen;
        do {
            j--;
            long xVal = ((long) x[j]) & M;
            long p = xVal * xVal;
            int k2 = k - 1;
            zz[k2] = (c << 31) | ((int) (p >>> 33));
            k = k2 - 1;
            zz[k] = (int) (p >>> 1);
            c = (int) p;
        } while (j > 0);
        long d = 0;
        int zzPos = 2;
        for (int i = 1; i < len; i++) {
            long d2 = d + (((long) squareWordAddTo(x, i, zz)) & M) + (((long) zz[zzPos]) & M);
            int zzPos2 = zzPos + 1;
            zz[zzPos] = (int) d2;
            long d3 = (d2 >>> 32) + (((long) zz[zzPos2]) & M);
            zzPos = zzPos2 + 1;
            zz[zzPos2] = (int) d3;
            d = d3 >>> 32;
        }
        shiftUpBit(extLen, zz, x[0] << 31);
    }

    public static void square(int len, int[] x, int xOff, int[] zz, int zzOff) {
        int extLen = len << 1;
        int c = 0;
        int j = len;
        int k = extLen;
        do {
            j--;
            long xVal = ((long) x[xOff + j]) & M;
            long p = xVal * xVal;
            int k2 = k - 1;
            zz[zzOff + k2] = (c << 31) | ((int) (p >>> 33));
            k = k2 - 1;
            zz[zzOff + k] = (int) (p >>> 1);
            c = (int) p;
        } while (j > 0);
        long d = 0;
        int zzPos = zzOff + 2;
        for (int i = 1; i < len; i++) {
            long d2 = d + (((long) squareWordAddTo(x, xOff, i, zz, zzOff)) & M) + (((long) zz[zzPos]) & M);
            int zzPos2 = zzPos + 1;
            zz[zzPos] = (int) d2;
            long d3 = (d2 >>> 32) + (((long) zz[zzPos2]) & M);
            zzPos = zzPos2 + 1;
            zz[zzPos2] = (int) d3;
            d = d3 >>> 32;
        }
        shiftUpBit(extLen, zz, zzOff, x[xOff] << 31);
    }

    public static int squareWordAddTo(int[] x, int xPos, int[] z) {
        long c = 0;
        long xVal = ((long) x[xPos]) & M;
        int i = 0;
        do {
            long c2 = c + ((((long) x[i]) & M) * xVal) + (((long) z[xPos + i]) & M);
            z[xPos + i] = (int) c2;
            c = c2 >>> 32;
            i++;
        } while (i < xPos);
        return (int) c;
    }

    public static int squareWordAddTo(int[] x, int xOff, int xPos, int[] z, int zOff) {
        long c = 0;
        long xVal = ((long) x[xOff + xPos]) & M;
        int i = 0;
        do {
            long c2 = c + ((((long) x[xOff + i]) & M) * xVal) + (((long) z[xPos + zOff]) & M);
            z[xPos + zOff] = (int) c2;
            c = c2 >>> 32;
            zOff++;
            i++;
        } while (i < xPos);
        return (int) c;
    }

    public static int sub(int len, int[] x, int[] y, int[] z) {
        long c = 0;
        for (int i = 0; i < len; i++) {
            long c2 = c + ((((long) x[i]) & M) - (((long) y[i]) & M));
            z[i] = (int) c2;
            c = c2 >> 32;
        }
        return (int) c;
    }

    public static int sub(int len, int[] x, int xOff, int[] y, int yOff, int[] z, int zOff) {
        long c = 0;
        for (int i = 0; i < len; i++) {
            long c2 = c + ((((long) x[xOff + i]) & M) - (((long) y[yOff + i]) & M));
            z[zOff + i] = (int) c2;
            c = c2 >> 32;
        }
        return (int) c;
    }

    public static int sub33At(int len, int x, int[] z, int zPos) {
        long c = (((long) z[zPos + 0]) & M) - (((long) x) & M);
        z[zPos + 0] = (int) c;
        long c2 = (c >> 32) + ((((long) z[zPos + 1]) & M) - 1);
        z[zPos + 1] = (int) c2;
        if ((c2 >> 32) == 0) {
            return 0;
        }
        return decAt(len, z, zPos + 2);
    }

    public static int sub33At(int len, int x, int[] z, int zOff, int zPos) {
        long c = (((long) z[zOff + zPos]) & M) - (((long) x) & M);
        z[zOff + zPos] = (int) c;
        long c2 = (c >> 32) + ((((long) z[(zOff + zPos) + 1]) & M) - 1);
        z[zOff + zPos + 1] = (int) c2;
        if ((c2 >> 32) == 0) {
            return 0;
        }
        return decAt(len, z, zOff, zPos + 2);
    }

    public static int sub33From(int len, int x, int[] z) {
        long c = (((long) z[0]) & M) - (((long) x) & M);
        z[0] = (int) c;
        long c2 = (c >> 32) + ((((long) z[1]) & M) - 1);
        z[1] = (int) c2;
        if ((c2 >> 32) == 0) {
            return 0;
        }
        return decAt(len, z, 2);
    }

    public static int sub33From(int len, int x, int[] z, int zOff) {
        long c = (((long) z[zOff + 0]) & M) - (((long) x) & M);
        z[zOff + 0] = (int) c;
        long c2 = (c >> 32) + ((((long) z[zOff + 1]) & M) - 1);
        z[zOff + 1] = (int) c2;
        if ((c2 >> 32) == 0) {
            return 0;
        }
        return decAt(len, z, zOff, 2);
    }

    public static int subBothFrom(int len, int[] x, int[] y, int[] z) {
        long c = 0;
        for (int i = 0; i < len; i++) {
            long c2 = c + (((((long) z[i]) & M) - (((long) x[i]) & M)) - (((long) y[i]) & M));
            z[i] = (int) c2;
            c = c2 >> 32;
        }
        return (int) c;
    }

    public static int subBothFrom(int len, int[] x, int xOff, int[] y, int yOff, int[] z, int zOff) {
        long c = 0;
        for (int i = 0; i < len; i++) {
            long c2 = c + (((((long) z[zOff + i]) & M) - (((long) x[xOff + i]) & M)) - (((long) y[yOff + i]) & M));
            z[zOff + i] = (int) c2;
            c = c2 >> 32;
        }
        return (int) c;
    }

    public static int subDWordAt(int len, long x, int[] z, int zPos) {
        long c = (((long) z[zPos + 0]) & M) - (x & M);
        z[zPos + 0] = (int) c;
        long c2 = (c >> 32) + ((((long) z[zPos + 1]) & M) - (x >>> 32));
        z[zPos + 1] = (int) c2;
        if ((c2 >> 32) == 0) {
            return 0;
        }
        return decAt(len, z, zPos + 2);
    }

    public static int subDWordAt(int len, long x, int[] z, int zOff, int zPos) {
        long c = (((long) z[zOff + zPos]) & M) - (x & M);
        z[zOff + zPos] = (int) c;
        long c2 = (c >> 32) + ((((long) z[(zOff + zPos) + 1]) & M) - (x >>> 32));
        z[zOff + zPos + 1] = (int) c2;
        if ((c2 >> 32) == 0) {
            return 0;
        }
        return decAt(len, z, zOff, zPos + 2);
    }

    public static int subDWordFrom(int len, long x, int[] z) {
        long c = (((long) z[0]) & M) - (x & M);
        z[0] = (int) c;
        long c2 = (c >> 32) + ((((long) z[1]) & M) - (x >>> 32));
        z[1] = (int) c2;
        if ((c2 >> 32) == 0) {
            return 0;
        }
        return decAt(len, z, 2);
    }

    public static int subDWordFrom(int len, long x, int[] z, int zOff) {
        long c = (((long) z[zOff + 0]) & M) - (x & M);
        z[zOff + 0] = (int) c;
        long c2 = (c >> 32) + ((((long) z[zOff + 1]) & M) - (x >>> 32));
        z[zOff + 1] = (int) c2;
        if ((c2 >> 32) == 0) {
            return 0;
        }
        return decAt(len, z, zOff, 2);
    }

    public static int subFrom(int len, int[] x, int[] z) {
        long c = 0;
        for (int i = 0; i < len; i++) {
            long c2 = c + ((((long) z[i]) & M) - (((long) x[i]) & M));
            z[i] = (int) c2;
            c = c2 >> 32;
        }
        return (int) c;
    }

    public static int subFrom(int len, int[] x, int xOff, int[] z, int zOff) {
        long c = 0;
        for (int i = 0; i < len; i++) {
            long c2 = c + ((((long) z[zOff + i]) & M) - (((long) x[xOff + i]) & M));
            z[zOff + i] = (int) c2;
            c = c2 >> 32;
        }
        return (int) c;
    }

    public static int subWordAt(int len, int x, int[] z, int zPos) {
        long c = (((long) z[zPos]) & M) - (((long) x) & M);
        z[zPos] = (int) c;
        if ((c >> 32) == 0) {
            return 0;
        }
        return decAt(len, z, zPos + 1);
    }

    public static int subWordAt(int len, int x, int[] z, int zOff, int zPos) {
        long c = (((long) z[zOff + zPos]) & M) - (((long) x) & M);
        z[zOff + zPos] = (int) c;
        if ((c >> 32) == 0) {
            return 0;
        }
        return decAt(len, z, zOff, zPos + 1);
    }

    public static int subWordFrom(int len, int x, int[] z) {
        long c = (((long) z[0]) & M) - (((long) x) & M);
        z[0] = (int) c;
        if ((c >> 32) == 0) {
            return 0;
        }
        return decAt(len, z, 1);
    }

    public static int subWordFrom(int len, int x, int[] z, int zOff) {
        long c = (((long) z[zOff + 0]) & M) - (((long) x) & M);
        z[zOff + 0] = (int) c;
        if ((c >> 32) == 0) {
            return 0;
        }
        return decAt(len, z, zOff, 1);
    }

    public static BigInteger toBigInteger(int len, int[] x) {
        byte[] bs = new byte[(len << 2)];
        for (int i = 0; i < len; i++) {
            int x_i = x[i];
            if (x_i != 0) {
                Pack.intToBigEndian(x_i, bs, ((len - 1) - i) << 2);
            }
        }
        return new BigInteger(1, bs);
    }

    public static void zero(int len, int[] z) {
        for (int i = 0; i < len; i++) {
            z[i] = 0;
        }
    }

    public static void zero(int len, int[] z, int zOff) {
        for (int i = 0; i < len; i++) {
            z[zOff + i] = 0;
        }
    }

    public static void zero64(int len, long[] z) {
        for (int i = 0; i < len; i++) {
            z[i] = 0;
        }
    }
}
