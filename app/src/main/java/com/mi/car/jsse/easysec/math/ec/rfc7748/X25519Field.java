package com.mi.car.jsse.easysec.math.ec.rfc7748;

import com.mi.car.jsse.easysec.math.raw.Mod;

public abstract class X25519Field {
    private static final int M24 = 16777215;
    private static final int M25 = 33554431;
    private static final int M26 = 67108863;
    private static final int[] P32 = {-19, -1, -1, -1, -1, -1, -1, Integer.MAX_VALUE};
    private static final int[] ROOT_NEG_ONE = {34513072, 59165138, 4688974, 3500415, 6194736, 33281959, 54535759, 32551604, 163342, 5703241};
    public static final int SIZE = 10;

    protected X25519Field() {
    }

    public static void add(int[] x, int[] y, int[] z) {
        for (int i = 0; i < 10; i++) {
            z[i] = x[i] + y[i];
        }
    }

    public static void addOne(int[] z) {
        z[0] = z[0] + 1;
    }

    public static void addOne(int[] z, int zOff) {
        z[zOff] = z[zOff] + 1;
    }

    public static void apm(int[] x, int[] y, int[] zp, int[] zm) {
        for (int i = 0; i < 10; i++) {
            int xi = x[i];
            int yi = y[i];
            zp[i] = xi + yi;
            zm[i] = xi - yi;
        }
    }

    public static int areEqual(int[] x, int[] y) {
        int d = 0;
        for (int i = 0; i < 10; i++) {
            d |= x[i] ^ y[i];
        }
        return (((d >>> 1) | (d & 1)) - 1) >> 31;
    }

    public static boolean areEqualVar(int[] x, int[] y) {
        return areEqual(x, y) != 0;
    }

    public static void carry(int[] z) {
        int z0 = z[0];
        int z1 = z[1];
        int z2 = z[2];
        int z3 = z[3];
        int z4 = z[4];
        int z5 = z[5];
        int z6 = z[6];
        int z7 = z[7];
        int z8 = z[8];
        int z9 = z[9];
        int z22 = z2 + (z1 >> 26);
        int z12 = z1 & M26;
        int z42 = z4 + (z3 >> 26);
        int z32 = z3 & M26;
        int z72 = z7 + (z6 >> 26);
        int z62 = z6 & M26;
        int z92 = z9 + (z8 >> 26);
        int z82 = z8 & M26;
        int z33 = z32 + (z22 >> 25);
        int z23 = z22 & M25;
        int z52 = z5 + (z42 >> 25);
        int z43 = z42 & M25;
        int z83 = z82 + (z72 >> 25);
        int z73 = z72 & M25;
        int z02 = z0 + ((z92 >> 25) * 38);
        int z93 = z92 & M25;
        int z13 = z12 + (z02 >> 26);
        int z03 = z02 & M26;
        int z63 = z62 + (z52 >> 26);
        int z53 = z52 & M26;
        int z24 = z23 + (z13 >> 26);
        int z14 = z13 & M26;
        int z44 = z43 + (z33 >> 26);
        int z34 = z33 & M26;
        int z74 = z73 + (z63 >> 26);
        int z64 = z63 & M26;
        int z84 = z83 & M26;
        z[0] = z03;
        z[1] = z14;
        z[2] = z24;
        z[3] = z34;
        z[4] = z44;
        z[5] = z53;
        z[6] = z64;
        z[7] = z74;
        z[8] = z84;
        z[9] = z93 + (z83 >> 26);
    }

    public static void cmov(int cond, int[] x, int xOff, int[] z, int zOff) {
        for (int i = 0; i < 10; i++) {
            int z_i = z[zOff + i];
            z[zOff + i] = z_i ^ ((z_i ^ x[xOff + i]) & cond);
        }
    }

    public static void cnegate(int negate, int[] z) {
        int mask = 0 - negate;
        for (int i = 0; i < 10; i++) {
            z[i] = (z[i] ^ mask) - mask;
        }
    }

    public static void copy(int[] x, int xOff, int[] z, int zOff) {
        for (int i = 0; i < 10; i++) {
            z[zOff + i] = x[xOff + i];
        }
    }

    public static int[] create() {
        return new int[10];
    }

    public static int[] createTable(int n) {
        return new int[(n * 10)];
    }

    public static void cswap(int swap, int[] a, int[] b) {
        int mask = 0 - swap;
        for (int i = 0; i < 10; i++) {
            int ai = a[i];
            int bi = b[i];
            int dummy = mask & (ai ^ bi);
            a[i] = ai ^ dummy;
            b[i] = bi ^ dummy;
        }
    }

    public static void decode(int[] x, int xOff, int[] z) {
        decode128(x, xOff, z, 0);
        decode128(x, xOff + 4, z, 5);
        z[9] = z[9] & M24;
    }

    public static void decode(byte[] x, int xOff, int[] z) {
        decode128(x, xOff, z, 0);
        decode128(x, xOff + 16, z, 5);
        z[9] = z[9] & M24;
    }

    private static void decode128(int[] is, int off, int[] z, int zOff) {
        int t0 = is[off + 0];
        int t1 = is[off + 1];
        int t2 = is[off + 2];
        int t3 = is[off + 3];
        z[zOff + 0] = t0 & M26;
        z[zOff + 1] = ((t1 << 6) | (t0 >>> 26)) & M26;
        z[zOff + 2] = ((t2 << 12) | (t1 >>> 20)) & M25;
        z[zOff + 3] = ((t3 << 19) | (t2 >>> 13)) & M26;
        z[zOff + 4] = t3 >>> 7;
    }

    private static void decode128(byte[] bs, int off, int[] z, int zOff) {
        int t0 = decode32(bs, off + 0);
        int t1 = decode32(bs, off + 4);
        int t2 = decode32(bs, off + 8);
        int t3 = decode32(bs, off + 12);
        z[zOff + 0] = t0 & M26;
        z[zOff + 1] = ((t1 << 6) | (t0 >>> 26)) & M26;
        z[zOff + 2] = ((t2 << 12) | (t1 >>> 20)) & M25;
        z[zOff + 3] = ((t3 << 19) | (t2 >>> 13)) & M26;
        z[zOff + 4] = t3 >>> 7;
    }

    private static int decode32(byte[] bs, int off) {
        int off2 = off + 1;
        int off3 = off2 + 1;
        return (bs[off] & 255) | ((bs[off2] & 255) << 8) | ((bs[off3] & 255) << 16) | (bs[off3 + 1] << 24);
    }

    public static void encode(int[] x, int[] z, int zOff) {
        encode128(x, 0, z, zOff);
        encode128(x, 5, z, zOff + 4);
    }

    public static void encode(int[] x, byte[] z, int zOff) {
        encode128(x, 0, z, zOff);
        encode128(x, 5, z, zOff + 16);
    }

    private static void encode128(int[] x, int xOff, int[] is, int off) {
        int x0 = x[xOff + 0];
        int x1 = x[xOff + 1];
        int x2 = x[xOff + 2];
        int x3 = x[xOff + 3];
        int x4 = x[xOff + 4];
        is[off + 0] = (x1 << 26) | x0;
        is[off + 1] = (x1 >>> 6) | (x2 << 20);
        is[off + 2] = (x2 >>> 12) | (x3 << 13);
        is[off + 3] = (x3 >>> 19) | (x4 << 7);
    }

    private static void encode128(int[] x, int xOff, byte[] bs, int off) {
        int x0 = x[xOff + 0];
        int x1 = x[xOff + 1];
        int x2 = x[xOff + 2];
        int x3 = x[xOff + 3];
        int x4 = x[xOff + 4];
        encode32(x0 | (x1 << 26), bs, off + 0);
        encode32((x1 >>> 6) | (x2 << 20), bs, off + 4);
        encode32((x2 >>> 12) | (x3 << 13), bs, off + 8);
        encode32((x3 >>> 19) | (x4 << 7), bs, off + 12);
    }

    private static void encode32(int n, byte[] bs, int off) {
        bs[off] = (byte) n;
        int off2 = off + 1;
        bs[off2] = (byte) (n >>> 8);
        int off3 = off2 + 1;
        bs[off3] = (byte) (n >>> 16);
        bs[off3 + 1] = (byte) (n >>> 24);
    }

    public static void inv(int[] x, int[] z) {
        int[] t = create();
        int[] u = new int[8];
        copy(x, 0, t, 0);
        normalize(t);
        encode(t, u, 0);
        Mod.modOddInverse(P32, u, u);
        decode(u, 0, z);
    }

    public static void invVar(int[] x, int[] z) {
        int[] t = create();
        int[] u = new int[8];
        copy(x, 0, t, 0);
        normalize(t);
        encode(t, u, 0);
        Mod.modOddInverseVar(P32, u, u);
        decode(u, 0, z);
    }

    public static int isOne(int[] x) {
        int d = x[0] ^ 1;
        for (int i = 1; i < 10; i++) {
            d |= x[i];
        }
        return (((d >>> 1) | (d & 1)) - 1) >> 31;
    }

    public static boolean isOneVar(int[] x) {
        return isOne(x) != 0;
    }

    public static int isZero(int[] x) {
        int d = 0;
        for (int i = 0; i < 10; i++) {
            d |= x[i];
        }
        return (((d >>> 1) | (d & 1)) - 1) >> 31;
    }

    public static boolean isZeroVar(int[] x) {
        return isZero(x) != 0;
    }

    public static void mul(int[] x, int y, int[] z) {
        int x0 = x[0];
        int x1 = x[1];
        int x2 = x[2];
        int x3 = x[3];
        int x4 = x[4];
        int x5 = x[5];
        int x6 = x[6];
        int x7 = x[7];
        int x8 = x[8];
        int x9 = x[9];
        long c0 = ((long) x2) * ((long) y);
        int x22 = ((int) c0) & M25;
        long c1 = ((long) x4) * ((long) y);
        int x42 = ((int) c1) & M25;
        long c2 = ((long) x7) * ((long) y);
        int x72 = ((int) c2) & M25;
        long c3 = ((long) x9) * ((long) y);
        int x92 = ((int) c3) & M25;
        long c32 = ((c3 >> 25) * 38) + (((long) x0) * ((long) y));
        z[0] = ((int) c32) & M26;
        long c12 = (c1 >> 25) + (((long) x5) * ((long) y));
        z[5] = ((int) c12) & M26;
        long c33 = (c32 >> 26) + (((long) x1) * ((long) y));
        z[1] = ((int) c33) & M26;
        long c02 = (c0 >> 25) + (((long) x3) * ((long) y));
        z[3] = ((int) c02) & M26;
        long c13 = (c12 >> 26) + (((long) x6) * ((long) y));
        z[6] = ((int) c13) & M26;
        long c22 = (c2 >> 25) + (((long) x8) * ((long) y));
        z[8] = ((int) c22) & M26;
        z[2] = ((int) (c33 >> 26)) + x22;
        z[4] = ((int) (c02 >> 26)) + x42;
        z[7] = ((int) (c13 >> 26)) + x72;
        z[9] = ((int) (c22 >> 26)) + x92;
    }

    public static void mul(int[] x, int[] y, int[] z) {
        int x0 = x[0];
        int y0 = y[0];
        int x1 = x[1];
        int y1 = y[1];
        int x2 = x[2];
        int y2 = y[2];
        int x3 = x[3];
        int y3 = y[3];
        int x4 = x[4];
        int y4 = y[4];
        int u0 = x[5];
        int v0 = y[5];
        int u1 = x[6];
        int v1 = y[6];
        int u2 = x[7];
        int v2 = y[7];
        int u3 = x[8];
        int v3 = y[8];
        int u4 = x[9];
        int v4 = y[9];
        long a4 = ((((long) x2) * ((long) y2)) << 1) + (((long) x0) * ((long) y4)) + (((long) x1) * ((long) y3)) + (((long) x3) * ((long) y1)) + (((long) x4) * ((long) y0));
        long b4 = ((((long) u2) * ((long) v2)) << 1) + (((long) u0) * ((long) v4)) + (((long) u1) * ((long) v3)) + (((long) u3) * ((long) v1)) + (((long) u4) * ((long) v0));
        long a0 = (((long) x0) * ((long) y0)) - (76 * ((((((long) u1) * ((long) v4)) + (((long) u2) * ((long) v3))) + (((long) u3) * ((long) v2))) + (((long) u4) * ((long) v1))));
        long a1 = ((((long) x0) * ((long) y1)) + (((long) x1) * ((long) y0))) - (38 * ((((((long) u2) * ((long) v4)) + (((long) u4) * ((long) v2))) << 1) + (((long) u3) * ((long) v3))));
        long a2 = (((((long) x0) * ((long) y2)) + (((long) x1) * ((long) y1))) + (((long) x2) * ((long) y0))) - (38 * ((((long) u3) * ((long) v4)) + (((long) u4) * ((long) v3))));
        long a3 = ((((((long) x1) * ((long) y2)) + (((long) x2) * ((long) y1))) << 1) + ((((long) x0) * ((long) y3)) + (((long) x3) * ((long) y0)))) - (76 * (((long) u4) * ((long) v4)));
        long a5 = (((((((long) x1) * ((long) y4)) + (((long) x2) * ((long) y3))) + (((long) x3) * ((long) y2))) + (((long) x4) * ((long) y1))) << 1) - (((long) u0) * ((long) v0));
        long a6 = ((((((long) x2) * ((long) y4)) + (((long) x4) * ((long) y2))) << 1) + (((long) x3) * ((long) y3))) - ((((long) u0) * ((long) v1)) + (((long) u1) * ((long) v0)));
        long a7 = ((((long) x3) * ((long) y4)) + (((long) x4) * ((long) y3))) - (((((long) u0) * ((long) v2)) + (((long) u1) * ((long) v1))) + (((long) u2) * ((long) v0)));
        long a8 = ((((long) x4) * ((long) y4)) << 1) - ((((((long) u1) * ((long) v2)) + (((long) u2) * ((long) v1))) << 1) + ((((long) u0) * ((long) v3)) + (((long) u3) * ((long) v0))));
        int x02 = x0 + u0;
        int y02 = y0 + v0;
        int x12 = x1 + u1;
        int y12 = y1 + v1;
        int x22 = x2 + u2;
        int y22 = y2 + v2;
        int x32 = x3 + u3;
        int y32 = y3 + v3;
        int x42 = x4 + u4;
        int y42 = y4 + v4;
        long t = a8 + (((((((long) x12) * ((long) y22)) + (((long) x22) * ((long) y12))) << 1) + ((((long) x02) * ((long) y32)) + (((long) x32) * ((long) y02)))) - a3);
        int z8 = ((int) t) & M26;
        long t2 = (t >> 26) + (((((((long) x22) * ((long) y22)) << 1) + ((((((long) x02) * ((long) y42)) + (((long) x12) * ((long) y32))) + (((long) x32) * ((long) y12))) + (((long) x42) * ((long) y02)))) - a4) - b4);
        int z9 = ((int) t2) & M25;
        long t3 = a0 + ((((t2 >> 25) + (((((((long) x12) * ((long) y42)) + (((long) x22) * ((long) y32))) + (((long) x32) * ((long) y22))) + (((long) x42) * ((long) y12))) << 1)) - a5) * 38);
        z[0] = ((int) t3) & M26;
        long t4 = (t3 >> 26) + ((((((((long) x22) * ((long) y42)) + (((long) x42) * ((long) y22))) << 1) + (((long) x32) * ((long) y32))) - a6) * 38) + a1;
        z[1] = ((int) t4) & M26;
        long t5 = (t4 >> 26) + ((((((long) x32) * ((long) y42)) + (((long) x42) * ((long) y32))) - a7) * 38) + a2;
        z[2] = ((int) t5) & M25;
        long t6 = (t5 >> 25) + ((((((long) x42) * ((long) y42)) << 1) - a8) * 38) + a3;
        z[3] = ((int) t6) & M26;
        long t7 = (t6 >> 26) + (38 * b4) + a4;
        z[4] = ((int) t7) & M25;
        long t8 = (t7 >> 25) + ((((long) x02) * ((long) y02)) - a0) + a5;
        z[5] = ((int) t8) & M26;
        long t9 = (t8 >> 26) + (((((long) x02) * ((long) y12)) + (((long) x12) * ((long) y02))) - a1) + a6;
        z[6] = ((int) t9) & M26;
        long t10 = (t9 >> 26) + ((((((long) x02) * ((long) y22)) + (((long) x12) * ((long) y12))) + (((long) x22) * ((long) y02))) - a2) + a7;
        z[7] = ((int) t10) & M25;
        long t11 = (t10 >> 25) + ((long) z8);
        z[8] = ((int) t11) & M26;
        z[9] = ((int) (t11 >> 26)) + z9;
    }

    public static void negate(int[] x, int[] z) {
        for (int i = 0; i < 10; i++) {
            z[i] = -x[i];
        }
    }

    public static void normalize(int[] z) {
        int x = (z[9] >>> 23) & 1;
        reduce(z, x);
        reduce(z, -x);
    }

    public static void one(int[] z) {
        z[0] = 1;
        for (int i = 1; i < 10; i++) {
            z[i] = 0;
        }
    }

    private static void powPm5d8(int[] x, int[] rx2, int[] rz) {
        sqr(x, rx2);
        mul(x, rx2, rx2);
        int[] x3 = create();
        sqr(rx2, x3);
        mul(x, x3, x3);
        sqr(x3, 2, x3);
        mul(rx2, x3, x3);
        int[] x10 = create();
        sqr(x3, 5, x10);
        mul(x3, x10, x10);
        int[] x15 = create();
        sqr(x10, 5, x15);
        mul(x3, x15, x15);
        sqr(x15, 10, x3);
        mul(x10, x3, x3);
        sqr(x3, 25, x10);
        mul(x3, x10, x10);
        sqr(x10, 25, x15);
        mul(x3, x15, x15);
        sqr(x15, 50, x3);
        mul(x10, x3, x3);
        sqr(x3, 125, x10);
        mul(x3, x10, x10);
        sqr(x10, 2, x3);
        mul(x3, x, rz);
    }

    private static void reduce(int[] z, int x) {
        int t = z[9];
        int z9 = t & M24;
        long cc = ((long) (((t >> 24) + x) * 19)) + ((long) z[0]);
        z[0] = ((int) cc) & M26;
        long cc2 = (cc >> 26) + ((long) z[1]);
        z[1] = ((int) cc2) & M26;
        long cc3 = (cc2 >> 26) + ((long) z[2]);
        z[2] = ((int) cc3) & M25;
        long cc4 = (cc3 >> 25) + ((long) z[3]);
        z[3] = ((int) cc4) & M26;
        long cc5 = (cc4 >> 26) + ((long) z[4]);
        z[4] = ((int) cc5) & M25;
        long cc6 = (cc5 >> 25) + ((long) z[5]);
        z[5] = ((int) cc6) & M26;
        long cc7 = (cc6 >> 26) + ((long) z[6]);
        z[6] = ((int) cc7) & M26;
        long cc8 = (cc7 >> 26) + ((long) z[7]);
        z[7] = ((int) cc8) & M25;
        long cc9 = (cc8 >> 25) + ((long) z[8]);
        z[8] = ((int) cc9) & M26;
        z[9] = ((int) (cc9 >> 26)) + z9;
    }

    public static void sqr(int[] x, int[] z) {
        int x0 = x[0];
        int x1 = x[1];
        int x2 = x[2];
        int x3 = x[3];
        int x4 = x[4];
        int u0 = x[5];
        int u1 = x[6];
        int u2 = x[7];
        int u3 = x[8];
        int u4 = x[9];
        int x1_2 = x1 * 2;
        int x2_2 = x2 * 2;
        int x3_2 = x3 * 2;
        int x4_2 = x4 * 2;
        long a4 = (((long) x2) * ((long) x2_2)) + (((long) x0) * ((long) x4_2)) + (((long) x1) * ((long) x3_2));
        int u1_2 = u1 * 2;
        int u2_2 = u2 * 2;
        int u3_2 = u3 * 2;
        int u4_2 = u4 * 2;
        long b4 = (((long) u2) * ((long) u2_2)) + (((long) u0) * ((long) u4_2)) + (((long) u1) * ((long) u3_2));
        long a0 = (((long) x0) * ((long) x0)) - (38 * ((((long) u1_2) * ((long) u4_2)) + (((long) u2_2) * ((long) u3_2))));
        long a1 = (((long) x0) * ((long) x1_2)) - (38 * ((((long) u2_2) * ((long) u4_2)) + (((long) u3) * ((long) u3))));
        long a2 = ((((long) x0) * ((long) x2_2)) + (((long) x1) * ((long) x1))) - (38 * (((long) u3) * ((long) u4_2)));
        long a3 = ((((long) x1_2) * ((long) x2_2)) + (((long) x0) * ((long) x3_2))) - (38 * (((long) u4) * ((long) u4_2)));
        long a5 = ((((long) x1_2) * ((long) x4_2)) + (((long) x2_2) * ((long) x3_2))) - (((long) u0) * ((long) u0));
        long a6 = ((((long) x2_2) * ((long) x4_2)) + (((long) x3) * ((long) x3))) - (((long) u0) * ((long) u1_2));
        long a7 = (((long) x3) * ((long) x4_2)) - ((((long) u0) * ((long) u2_2)) + (((long) u1) * ((long) u1)));
        long a8 = (((long) x4) * ((long) x4_2)) - ((((long) u1_2) * ((long) u2_2)) + (((long) u0) * ((long) u3_2)));
        int x02 = x0 + u0;
        int x12 = x1 + u1;
        int x22 = x2 + u2;
        int x32 = x3 + u3;
        int x42 = x4 + u4;
        int x1_22 = x12 * 2;
        int x2_22 = x22 * 2;
        int x3_22 = x32 * 2;
        int x4_22 = x42 * 2;
        long t = a8 + (((((long) x1_22) * ((long) x2_22)) + (((long) x02) * ((long) x3_22))) - a3);
        int z8 = ((int) t) & M26;
        long t2 = (t >> 26) + (((((((long) x22) * ((long) x2_22)) + (((long) x02) * ((long) x4_22))) + (((long) x12) * ((long) x3_22))) - a4) - b4);
        int z9 = ((int) t2) & M25;
        long t3 = a0 + ((((t2 >> 25) + ((((long) x1_22) * ((long) x4_22)) + (((long) x2_22) * ((long) x3_22)))) - a5) * 38);
        z[0] = ((int) t3) & M26;
        long t4 = (t3 >> 26) + ((((((long) x2_22) * ((long) x4_22)) + (((long) x32) * ((long) x32))) - a6) * 38) + a1;
        z[1] = ((int) t4) & M26;
        long t5 = (t4 >> 26) + (((((long) x32) * ((long) x4_22)) - a7) * 38) + a2;
        z[2] = ((int) t5) & M25;
        long t6 = (t5 >> 25) + (((((long) x42) * ((long) x4_22)) - a8) * 38) + a3;
        z[3] = ((int) t6) & M26;
        long t7 = (t6 >> 26) + (38 * b4) + a4;
        z[4] = ((int) t7) & M25;
        long t8 = (t7 >> 25) + ((((long) x02) * ((long) x02)) - a0) + a5;
        z[5] = ((int) t8) & M26;
        long t9 = (t8 >> 26) + ((((long) x02) * ((long) x1_22)) - a1) + a6;
        z[6] = ((int) t9) & M26;
        long t10 = (t9 >> 26) + (((((long) x02) * ((long) x2_22)) + (((long) x12) * ((long) x12))) - a2) + a7;
        z[7] = ((int) t10) & M25;
        long t11 = (t10 >> 25) + ((long) z8);
        z[8] = ((int) t11) & M26;
        z[9] = ((int) (t11 >> 26)) + z9;
    }

    public static void sqr(int[] x, int n, int[] z) {
        sqr(x, z);
        while (true) {
            n--;
            if (n > 0) {
                sqr(z, z);
            } else {
                return;
            }
        }
    }

    public static boolean sqrtRatioVar(int[] u, int[] v, int[] z) {
        int[] uv3 = create();
        int[] uv7 = create();
        mul(u, v, uv3);
        sqr(v, uv7);
        mul(uv3, uv7, uv3);
        sqr(uv7, uv7);
        mul(uv7, uv3, uv7);
        int[] t = create();
        int[] x = create();
        powPm5d8(uv7, t, x);
        mul(x, uv3, x);
        int[] vx2 = create();
        sqr(x, vx2);
        mul(vx2, v, vx2);
        sub(vx2, u, t);
        normalize(t);
        if (isZeroVar(t)) {
            copy(x, 0, z, 0);
            return true;
        }
        add(vx2, u, t);
        normalize(t);
        if (!isZeroVar(t)) {
            return false;
        }
        mul(x, ROOT_NEG_ONE, z);
        return true;
    }

    public static void sub(int[] x, int[] y, int[] z) {
        for (int i = 0; i < 10; i++) {
            z[i] = x[i] - y[i];
        }
    }

    public static void subOne(int[] z) {
        z[0] = z[0] - 1;
    }

    public static void zero(int[] z) {
        for (int i = 0; i < 10; i++) {
            z[i] = 0;
        }
    }
}
