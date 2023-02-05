package com.mi.car.jsse.easysec.math.ec.rfc7748;

import com.mi.car.jsse.easysec.math.raw.Mod;

public abstract class X448Field {
    private static final int M28 = 268435455;
    private static final int[] P32 = {-1, -1, -1, -1, -1, -1, -1, -2, -1, -1, -1, -1, -1, -1};
    public static final int SIZE = 16;
    private static final long U32 = 4294967295L;

    protected X448Field() {
    }

    public static void add(int[] x, int[] y, int[] z) {
        for (int i = 0; i < 16; i++) {
            z[i] = x[i] + y[i];
        }
    }

    public static void addOne(int[] z) {
        z[0] = z[0] + 1;
    }

    public static void addOne(int[] z, int zOff) {
        z[zOff] = z[zOff] + 1;
    }

    public static int areEqual(int[] x, int[] y) {
        int d = 0;
        for (int i = 0; i < 16; i++) {
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
        int z10 = z[10];
        int z11 = z[11];
        int z12 = z[12];
        int z13 = z[13];
        int z14 = z[14];
        int z15 = z[15];
        int z16 = z1 + (z0 >>> 28);
        int z02 = z0 & M28;
        int z52 = z5 + (z4 >>> 28);
        int z42 = z4 & M28;
        int z92 = z9 + (z8 >>> 28);
        int z82 = z8 & M28;
        int z132 = z13 + (z12 >>> 28);
        int z122 = z12 & M28;
        int z22 = z2 + (z16 >>> 28);
        int z17 = z16 & M28;
        int z62 = z6 + (z52 >>> 28);
        int z53 = z52 & M28;
        int z102 = z10 + (z92 >>> 28);
        int z93 = z92 & M28;
        int z142 = z14 + (z132 >>> 28);
        int z133 = z132 & M28;
        int z32 = z3 + (z22 >>> 28);
        int z23 = z22 & M28;
        int z72 = z7 + (z62 >>> 28);
        int z63 = z62 & M28;
        int z112 = z11 + (z102 >>> 28);
        int z103 = z102 & M28;
        int z152 = z15 + (z142 >>> 28);
        int z143 = z142 & M28;
        int t = z152 >>> 28;
        int z153 = z152 & M28;
        int z03 = z02 + t;
        int z43 = z42 + (z32 >>> 28);
        int z33 = z32 & M28;
        int z83 = z82 + t + (z72 >>> 28);
        int z73 = z72 & M28;
        int z123 = z122 + (z112 >>> 28);
        int z113 = z112 & M28;
        int z18 = z17 + (z03 >>> 28);
        int z04 = z03 & M28;
        int z54 = z53 + (z43 >>> 28);
        int z44 = z43 & M28;
        int z94 = z93 + (z83 >>> 28);
        int z84 = z83 & M28;
        int z124 = z123 & M28;
        z[0] = z04;
        z[1] = z18;
        z[2] = z23;
        z[3] = z33;
        z[4] = z44;
        z[5] = z54;
        z[6] = z63;
        z[7] = z73;
        z[8] = z84;
        z[9] = z94;
        z[10] = z103;
        z[11] = z113;
        z[12] = z124;
        z[13] = z133 + (z123 >>> 28);
        z[14] = z143;
        z[15] = z153;
    }

    public static void cmov(int cond, int[] x, int xOff, int[] z, int zOff) {
        for (int i = 0; i < 16; i++) {
            int z_i = z[zOff + i];
            z[zOff + i] = z_i ^ ((z_i ^ x[xOff + i]) & cond);
        }
    }

    public static void cnegate(int negate, int[] z) {
        int[] t = create();
        sub(t, z, t);
        cmov(-negate, t, 0, z, 0);
    }

    public static void copy(int[] x, int xOff, int[] z, int zOff) {
        for (int i = 0; i < 16; i++) {
            z[zOff + i] = x[xOff + i];
        }
    }

    public static int[] create() {
        return new int[16];
    }

    public static int[] createTable(int n) {
        return new int[(n * 16)];
    }

    public static void cswap(int swap, int[] a, int[] b) {
        int mask = 0 - swap;
        for (int i = 0; i < 16; i++) {
            int ai = a[i];
            int bi = b[i];
            int dummy = mask & (ai ^ bi);
            a[i] = ai ^ dummy;
            b[i] = bi ^ dummy;
        }
    }

    public static void decode(int[] x, int xOff, int[] z) {
        decode224(x, xOff, z, 0);
        decode224(x, xOff + 7, z, 8);
    }

    public static void decode(byte[] x, int xOff, int[] z) {
        decode56(x, xOff, z, 0);
        decode56(x, xOff + 7, z, 2);
        decode56(x, xOff + 14, z, 4);
        decode56(x, xOff + 21, z, 6);
        decode56(x, xOff + 28, z, 8);
        decode56(x, xOff + 35, z, 10);
        decode56(x, xOff + 42, z, 12);
        decode56(x, xOff + 49, z, 14);
    }

    private static void decode224(int[] x, int xOff, int[] z, int zOff) {
        int x0 = x[xOff + 0];
        int x1 = x[xOff + 1];
        int x2 = x[xOff + 2];
        int x3 = x[xOff + 3];
        int x4 = x[xOff + 4];
        int x5 = x[xOff + 5];
        int x6 = x[xOff + 6];
        z[zOff + 0] = x0 & M28;
        z[zOff + 1] = ((x0 >>> 28) | (x1 << 4)) & M28;
        z[zOff + 2] = ((x1 >>> 24) | (x2 << 8)) & M28;
        z[zOff + 3] = ((x2 >>> 20) | (x3 << 12)) & M28;
        z[zOff + 4] = ((x3 >>> 16) | (x4 << 16)) & M28;
        z[zOff + 5] = ((x4 >>> 12) | (x5 << 20)) & M28;
        z[zOff + 6] = ((x5 >>> 8) | (x6 << 24)) & M28;
        z[zOff + 7] = x6 >>> 4;
    }

    private static int decode24(byte[] bs, int off) {
        int off2 = off + 1;
        return (bs[off] & 255) | ((bs[off2] & 255) << 8) | ((bs[off2 + 1] & 255) << 16);
    }

    private static int decode32(byte[] bs, int off) {
        int off2 = off + 1;
        int off3 = off2 + 1;
        return (bs[off] & 255) | ((bs[off2] & 255) << 8) | ((bs[off3] & 255) << 16) | (bs[off3 + 1] << 24);
    }

    private static void decode56(byte[] bs, int off, int[] z, int zOff) {
        int lo = decode32(bs, off);
        int hi = decode24(bs, off + 4);
        z[zOff] = M28 & lo;
        z[zOff + 1] = (lo >>> 28) | (hi << 4);
    }

    public static void encode(int[] x, int[] z, int zOff) {
        encode224(x, 0, z, zOff);
        encode224(x, 8, z, zOff + 7);
    }

    public static void encode(int[] x, byte[] z, int zOff) {
        encode56(x, 0, z, zOff);
        encode56(x, 2, z, zOff + 7);
        encode56(x, 4, z, zOff + 14);
        encode56(x, 6, z, zOff + 21);
        encode56(x, 8, z, zOff + 28);
        encode56(x, 10, z, zOff + 35);
        encode56(x, 12, z, zOff + 42);
        encode56(x, 14, z, zOff + 49);
    }

    private static void encode224(int[] x, int xOff, int[] is, int off) {
        int x0 = x[xOff + 0];
        int x1 = x[xOff + 1];
        int x2 = x[xOff + 2];
        int x3 = x[xOff + 3];
        int x4 = x[xOff + 4];
        int x5 = x[xOff + 5];
        int x6 = x[xOff + 6];
        int x7 = x[xOff + 7];
        is[off + 0] = (x1 << 28) | x0;
        is[off + 1] = (x1 >>> 4) | (x2 << 24);
        is[off + 2] = (x2 >>> 8) | (x3 << 20);
        is[off + 3] = (x3 >>> 12) | (x4 << 16);
        is[off + 4] = (x4 >>> 16) | (x5 << 12);
        is[off + 5] = (x5 >>> 20) | (x6 << 8);
        is[off + 6] = (x6 >>> 24) | (x7 << 4);
    }

    private static void encode24(int n, byte[] bs, int off) {
        bs[off] = (byte) n;
        int off2 = off + 1;
        bs[off2] = (byte) (n >>> 8);
        bs[off2 + 1] = (byte) (n >>> 16);
    }

    private static void encode32(int n, byte[] bs, int off) {
        bs[off] = (byte) n;
        int off2 = off + 1;
        bs[off2] = (byte) (n >>> 8);
        int off3 = off2 + 1;
        bs[off3] = (byte) (n >>> 16);
        bs[off3 + 1] = (byte) (n >>> 24);
    }

    private static void encode56(int[] x, int xOff, byte[] bs, int off) {
        int lo = x[xOff];
        int hi = x[xOff + 1];
        encode32((hi << 28) | lo, bs, off);
        encode24(hi >>> 4, bs, off + 4);
    }

    public static void inv(int[] x, int[] z) {
        int[] t = create();
        int[] u = new int[14];
        copy(x, 0, t, 0);
        normalize(t);
        encode(t, u, 0);
        Mod.modOddInverse(P32, u, u);
        decode(u, 0, z);
    }

    public static void invVar(int[] x, int[] z) {
        int[] t = create();
        int[] u = new int[14];
        copy(x, 0, t, 0);
        normalize(t);
        encode(t, u, 0);
        Mod.modOddInverseVar(P32, u, u);
        decode(u, 0, z);
    }

    public static int isOne(int[] x) {
        int d = x[0] ^ 1;
        for (int i = 1; i < 16; i++) {
            d |= x[i];
        }
        return (((d >>> 1) | (d & 1)) - 1) >> 31;
    }

    public static boolean isOneVar(int[] x) {
        return isOne(x) != 0;
    }

    public static int isZero(int[] x) {
        int d = 0;
        for (int i = 0; i < 16; i++) {
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
        int x10 = x[10];
        int x11 = x[11];
        int x12 = x[12];
        int x13 = x[13];
        int x14 = x[14];
        int x15 = x[15];
        long c = ((long) x1) * ((long) y);
        int z1 = ((int) c) & M28;
        long d = ((long) x5) * ((long) y);
        int z5 = ((int) d) & M28;
        long e = ((long) x9) * ((long) y);
        int z9 = ((int) e) & M28;
        long f = ((long) x13) * ((long) y);
        int z13 = ((int) f) & M28;
        long c2 = (c >>> 28) + (((long) x2) * ((long) y));
        z[2] = ((int) c2) & M28;
        long d2 = (d >>> 28) + (((long) x6) * ((long) y));
        z[6] = ((int) d2) & M28;
        long e2 = (e >>> 28) + (((long) x10) * ((long) y));
        z[10] = ((int) e2) & M28;
        long f2 = (f >>> 28) + (((long) x14) * ((long) y));
        z[14] = ((int) f2) & M28;
        long c3 = (c2 >>> 28) + (((long) x3) * ((long) y));
        z[3] = ((int) c3) & M28;
        long d3 = (d2 >>> 28) + (((long) x7) * ((long) y));
        z[7] = ((int) d3) & M28;
        long e3 = (e2 >>> 28) + (((long) x11) * ((long) y));
        z[11] = ((int) e3) & M28;
        long f3 = (f2 >>> 28) + (((long) x15) * ((long) y));
        z[15] = ((int) f3) & M28;
        long f4 = f3 >>> 28;
        long c4 = (c3 >>> 28) + (((long) x4) * ((long) y));
        z[4] = ((int) c4) & M28;
        long d4 = (d3 >>> 28) + f4 + (((long) x8) * ((long) y));
        z[8] = ((int) d4) & M28;
        long e4 = (e3 >>> 28) + (((long) x12) * ((long) y));
        z[12] = ((int) e4) & M28;
        long f5 = f4 + (((long) x0) * ((long) y));
        z[0] = ((int) f5) & M28;
        z[1] = ((int) (f5 >>> 28)) + z1;
        z[5] = ((int) (c4 >>> 28)) + z5;
        z[9] = ((int) (d4 >>> 28)) + z9;
        z[13] = ((int) (e4 >>> 28)) + z13;
    }

    public static void mul(int[] x, int[] y, int[] z) {
        int x0 = x[0];
        int x1 = x[1];
        int x2 = x[2];
        int x3 = x[3];
        int x4 = x[4];
        int x5 = x[5];
        int x6 = x[6];
        int x7 = x[7];
        int u0 = x[8];
        int u1 = x[9];
        int u2 = x[10];
        int u3 = x[11];
        int u4 = x[12];
        int u5 = x[13];
        int u6 = x[14];
        int u7 = x[15];
        int y0 = y[0];
        int y1 = y[1];
        int y2 = y[2];
        int y3 = y[3];
        int y4 = y[4];
        int y5 = y[5];
        int y6 = y[6];
        int y7 = y[7];
        int v0 = y[8];
        int v1 = y[9];
        int v2 = y[10];
        int v3 = y[11];
        int v4 = y[12];
        int v5 = y[13];
        int v6 = y[14];
        int v7 = y[15];
        int s0 = x0 + u0;
        int s1 = x1 + u1;
        int s2 = x2 + u2;
        int s3 = x3 + u3;
        int s4 = x4 + u4;
        int s5 = x5 + u5;
        int s6 = x6 + u6;
        int s7 = x7 + u7;
        int t0 = y0 + v0;
        int t1 = y1 + v1;
        int t2 = y2 + v2;
        int t3 = y3 + v3;
        int t4 = y4 + v4;
        int t5 = y5 + v5;
        int t6 = y6 + v6;
        int t7 = y7 + v7;
        long f0 = ((long) x0) * ((long) y0);
        long h8 = (((long) s7) * ((long) t1)) + (((long) s6) * ((long) t2)) + (((long) s5) * ((long) t3)) + (((long) s4) * ((long) t4)) + (((long) s3) * ((long) t5)) + (((long) s2) * ((long) t6)) + (((long) s1) * ((long) t7));
        long c = ((f0 + (((long) u0) * ((long) v0))) + h8) - (((((((((long) x7) * ((long) y1)) + (((long) x6) * ((long) y2))) + (((long) x5) * ((long) y3))) + (((long) x4) * ((long) y4))) + (((long) x3) * ((long) y5))) + (((long) x2) * ((long) y6))) + (((long) x1) * ((long) y7)));
        int z0 = ((int) c) & M28;
        long d = (((((((((((long) u7) * ((long) v1)) + (((long) u6) * ((long) v2))) + (((long) u5) * ((long) v3))) + (((long) u4) * ((long) v4))) + (((long) u3) * ((long) v5))) + (((long) u2) * ((long) v6))) + (((long) u1) * ((long) v7))) + (((long) s0) * ((long) t0))) - f0) + h8;
        int z8 = ((int) d) & M28;
        long f1 = (((long) x1) * ((long) y0)) + (((long) x0) * ((long) y1));
        long h9 = (((long) s7) * ((long) t2)) + (((long) s6) * ((long) t3)) + (((long) s5) * ((long) t4)) + (((long) s4) * ((long) t5)) + (((long) s3) * ((long) t6)) + (((long) s2) * ((long) t7));
        long c2 = (c >>> 28) + (((f1 + ((((long) u1) * ((long) v0)) + (((long) u0) * ((long) v1)))) + h9) - ((((((((long) x7) * ((long) y2)) + (((long) x6) * ((long) y3))) + (((long) x5) * ((long) y4))) + (((long) x4) * ((long) y5))) + (((long) x3) * ((long) y6))) + (((long) x2) * ((long) y7))));
        int z1 = ((int) c2) & M28;
        long d2 = (d >>> 28) + ((((((((((long) u7) * ((long) v2)) + (((long) u6) * ((long) v3))) + (((long) u5) * ((long) v4))) + (((long) u4) * ((long) v5))) + (((long) u3) * ((long) v6))) + (((long) u2) * ((long) v7))) + ((((long) s1) * ((long) t0)) + (((long) s0) * ((long) t1)))) - f1) + h9;
        int z9 = ((int) d2) & M28;
        long f2 = (((long) x2) * ((long) y0)) + (((long) x1) * ((long) y1)) + (((long) x0) * ((long) y2));
        long h10 = (((long) s7) * ((long) t3)) + (((long) s6) * ((long) t4)) + (((long) s5) * ((long) t5)) + (((long) s4) * ((long) t6)) + (((long) s3) * ((long) t7));
        long c3 = (c2 >>> 28) + (((f2 + (((((long) u2) * ((long) v0)) + (((long) u1) * ((long) v1))) + (((long) u0) * ((long) v2)))) + h10) - (((((((long) x7) * ((long) y3)) + (((long) x6) * ((long) y4))) + (((long) x5) * ((long) y5))) + (((long) x4) * ((long) y6))) + (((long) x3) * ((long) y7))));
        int z2 = ((int) c3) & M28;
        long d3 = (d2 >>> 28) + (((((((((long) u7) * ((long) v3)) + (((long) u6) * ((long) v4))) + (((long) u5) * ((long) v5))) + (((long) u4) * ((long) v6))) + (((long) u3) * ((long) v7))) + (((((long) s2) * ((long) t0)) + (((long) s1) * ((long) t1))) + (((long) s0) * ((long) t2)))) - f2) + h10;
        int z10 = ((int) d3) & M28;
        long f3 = (((long) x3) * ((long) y0)) + (((long) x2) * ((long) y1)) + (((long) x1) * ((long) y2)) + (((long) x0) * ((long) y3));
        long h11 = (((long) s7) * ((long) t4)) + (((long) s6) * ((long) t5)) + (((long) s5) * ((long) t6)) + (((long) s4) * ((long) t7));
        long c4 = (c3 >>> 28) + (((f3 + ((((((long) u3) * ((long) v0)) + (((long) u2) * ((long) v1))) + (((long) u1) * ((long) v2))) + (((long) u0) * ((long) v3)))) + h11) - ((((((long) x7) * ((long) y4)) + (((long) x6) * ((long) y5))) + (((long) x5) * ((long) y6))) + (((long) x4) * ((long) y7))));
        int z3 = ((int) c4) & M28;
        long d4 = (d3 >>> 28) + ((((((((long) u7) * ((long) v4)) + (((long) u6) * ((long) v5))) + (((long) u5) * ((long) v6))) + (((long) u4) * ((long) v7))) + ((((((long) s3) * ((long) t0)) + (((long) s2) * ((long) t1))) + (((long) s1) * ((long) t2))) + (((long) s0) * ((long) t3)))) - f3) + h11;
        int z11 = ((int) d4) & M28;
        long f4 = (((long) x4) * ((long) y0)) + (((long) x3) * ((long) y1)) + (((long) x2) * ((long) y2)) + (((long) x1) * ((long) y3)) + (((long) x0) * ((long) y4));
        long h12 = (((long) s7) * ((long) t5)) + (((long) s6) * ((long) t6)) + (((long) s5) * ((long) t7));
        long c5 = (c4 >>> 28) + (((f4 + (((((((long) u4) * ((long) v0)) + (((long) u3) * ((long) v1))) + (((long) u2) * ((long) v2))) + (((long) u1) * ((long) v3))) + (((long) u0) * ((long) v4)))) + h12) - (((((long) x7) * ((long) y5)) + (((long) x6) * ((long) y6))) + (((long) x5) * ((long) y7))));
        int z4 = ((int) c5) & M28;
        long d5 = (d4 >>> 28) + (((((((long) u7) * ((long) v5)) + (((long) u6) * ((long) v6))) + (((long) u5) * ((long) v7))) + (((((((long) s4) * ((long) t0)) + (((long) s3) * ((long) t1))) + (((long) s2) * ((long) t2))) + (((long) s1) * ((long) t3))) + (((long) s0) * ((long) t4)))) - f4) + h12;
        int z12 = ((int) d5) & M28;
        long f5 = (((long) x5) * ((long) y0)) + (((long) x4) * ((long) y1)) + (((long) x3) * ((long) y2)) + (((long) x2) * ((long) y3)) + (((long) x1) * ((long) y4)) + (((long) x0) * ((long) y5));
        long h13 = (((long) s7) * ((long) t6)) + (((long) s6) * ((long) t7));
        long c6 = (c5 >>> 28) + (((f5 + ((((((((long) u5) * ((long) v0)) + (((long) u4) * ((long) v1))) + (((long) u3) * ((long) v2))) + (((long) u2) * ((long) v3))) + (((long) u1) * ((long) v4))) + (((long) u0) * ((long) v5)))) + h13) - ((((long) x7) * ((long) y6)) + (((long) x6) * ((long) y7))));
        int z5 = ((int) c6) & M28;
        long d6 = (d5 >>> 28) + ((((((long) u7) * ((long) v6)) + (((long) u6) * ((long) v7))) + ((((((((long) s5) * ((long) t0)) + (((long) s4) * ((long) t1))) + (((long) s3) * ((long) t2))) + (((long) s2) * ((long) t3))) + (((long) s1) * ((long) t4))) + (((long) s0) * ((long) t5)))) - f5) + h13;
        int z13 = ((int) d6) & M28;
        long f6 = (((long) x6) * ((long) y0)) + (((long) x5) * ((long) y1)) + (((long) x4) * ((long) y2)) + (((long) x3) * ((long) y3)) + (((long) x2) * ((long) y4)) + (((long) x1) * ((long) y5)) + (((long) x0) * ((long) y6));
        long h14 = ((long) s7) * ((long) t7);
        long c7 = (c6 >>> 28) + (((f6 + (((((((((long) u6) * ((long) v0)) + (((long) u5) * ((long) v1))) + (((long) u4) * ((long) v2))) + (((long) u3) * ((long) v3))) + (((long) u2) * ((long) v4))) + (((long) u1) * ((long) v5))) + (((long) u0) * ((long) v6)))) + h14) - (((long) x7) * ((long) y7)));
        int z6 = ((int) c7) & M28;
        long d7 = (d6 >>> 28) + (((((long) u7) * ((long) v7)) + (((((((((long) s6) * ((long) t0)) + (((long) s5) * ((long) t1))) + (((long) s4) * ((long) t2))) + (((long) s3) * ((long) t3))) + (((long) s2) * ((long) t4))) + (((long) s1) * ((long) t5))) + (((long) s0) * ((long) t6)))) - f6) + h14;
        int z14 = ((int) d7) & M28;
        long f7 = (((long) x7) * ((long) y0)) + (((long) x6) * ((long) y1)) + (((long) x5) * ((long) y2)) + (((long) x4) * ((long) y3)) + (((long) x3) * ((long) y4)) + (((long) x2) * ((long) y5)) + (((long) x1) * ((long) y6)) + (((long) x0) * ((long) y7));
        long c8 = (c7 >>> 28) + f7 + (((long) u7) * ((long) v0)) + (((long) u6) * ((long) v1)) + (((long) u5) * ((long) v2)) + (((long) u4) * ((long) v3)) + (((long) u3) * ((long) v4)) + (((long) u2) * ((long) v5)) + (((long) u1) * ((long) v6)) + (((long) u0) * ((long) v7));
        int z7 = ((int) c8) & M28;
        long d8 = (d7 >>> 28) + (((((((((((long) s7) * ((long) t0)) + (((long) s6) * ((long) t1))) + (((long) s5) * ((long) t2))) + (((long) s4) * ((long) t3))) + (((long) s3) * ((long) t4))) + (((long) s2) * ((long) t5))) + (((long) s1) * ((long) t6))) + (((long) s0) * ((long) t7))) - f7);
        int z15 = ((int) d8) & M28;
        long d9 = d8 >>> 28;
        long c9 = (c8 >>> 28) + d9 + ((long) z8);
        int z82 = ((int) c9) & M28;
        long d10 = d9 + ((long) z0);
        z[0] = ((int) d10) & M28;
        z[1] = z1 + ((int) (d10 >>> 28));
        z[2] = z2;
        z[3] = z3;
        z[4] = z4;
        z[5] = z5;
        z[6] = z6;
        z[7] = z7;
        z[8] = z82;
        z[9] = z9 + ((int) (c9 >>> 28));
        z[10] = z10;
        z[11] = z11;
        z[12] = z12;
        z[13] = z13;
        z[14] = z14;
        z[15] = z15;
    }

    public static void negate(int[] x, int[] z) {
        sub(create(), x, z);
    }

    public static void normalize(int[] z) {
        reduce(z, 1);
        reduce(z, -1);
    }

    public static void one(int[] z) {
        z[0] = 1;
        for (int i = 1; i < 16; i++) {
            z[i] = 0;
        }
    }

    private static void powPm3d4(int[] x, int[] z) {
        int[] x2 = create();
        sqr(x, x2);
        mul(x, x2, x2);
        int[] x3 = create();
        sqr(x2, x3);
        mul(x, x3, x3);
        int[] x6 = create();
        sqr(x3, 3, x6);
        mul(x3, x6, x6);
        int[] x9 = create();
        sqr(x6, 3, x9);
        mul(x3, x9, x9);
        int[] x18 = create();
        sqr(x9, 9, x18);
        mul(x9, x18, x18);
        int[] x19 = create();
        sqr(x18, x19);
        mul(x, x19, x19);
        int[] x37 = create();
        sqr(x19, 18, x37);
        mul(x18, x37, x37);
        int[] x74 = create();
        sqr(x37, 37, x74);
        mul(x37, x74, x74);
        int[] x111 = create();
        sqr(x74, 37, x111);
        mul(x37, x111, x111);
        int[] x222 = create();
        sqr(x111, 111, x222);
        mul(x111, x222, x222);
        int[] x223 = create();
        sqr(x222, x223);
        mul(x, x223, x223);
        int[] t = create();
        sqr(x223, 223, t);
        mul(t, x222, z);
    }

    private static void reduce(int[] z, int x) {
        int t = z[15];
        int z15 = t & M28;
        int t2 = (t >>> 28) + x;
        long cc = (long) t2;
        for (int i = 0; i < 8; i++) {
            long cc2 = cc + (((long) z[i]) & U32);
            z[i] = ((int) cc2) & M28;
            cc = cc2 >> 28;
        }
        long cc3 = cc + ((long) t2);
        for (int i2 = 8; i2 < 15; i2++) {
            long cc4 = cc3 + (((long) z[i2]) & U32);
            z[i2] = ((int) cc4) & M28;
            cc3 = cc4 >> 28;
        }
        z[15] = ((int) cc3) + z15;
    }

    public static void sqr(int[] x, int[] z) {
        int x0 = x[0];
        int x1 = x[1];
        int x2 = x[2];
        int x3 = x[3];
        int x4 = x[4];
        int x5 = x[5];
        int x6 = x[6];
        int x7 = x[7];
        int u0 = x[8];
        int u1 = x[9];
        int u2 = x[10];
        int u3 = x[11];
        int u4 = x[12];
        int u5 = x[13];
        int u6 = x[14];
        int u7 = x[15];
        int x0_2 = x0 * 2;
        int x1_2 = x1 * 2;
        int x2_2 = x2 * 2;
        int x3_2 = x3 * 2;
        int x4_2 = x4 * 2;
        int x5_2 = x5 * 2;
        int u0_2 = u0 * 2;
        int u1_2 = u1 * 2;
        int u2_2 = u2 * 2;
        int u3_2 = u3 * 2;
        int u4_2 = u4 * 2;
        int u5_2 = u5 * 2;
        int s0 = x0 + u0;
        int s1 = x1 + u1;
        int s2 = x2 + u2;
        int s3 = x3 + u3;
        int s4 = x4 + u4;
        int s5 = x5 + u5;
        int s6 = x6 + u6;
        int s7 = x7 + u7;
        int s0_2 = s0 * 2;
        int s1_2 = s1 * 2;
        int s2_2 = s2 * 2;
        int s3_2 = s3 * 2;
        int s4_2 = s4 * 2;
        int s5_2 = s5 * 2;
        long f0 = ((long) x0) * ((long) x0);
        long h8 = (((long) s7) * (((long) s1_2) & U32)) + (((long) s6) * (((long) s2_2) & U32)) + (((long) s5) * (((long) s3_2) & U32)) + (((long) s4) * ((long) s4));
        long c = ((f0 + (((long) u0) * ((long) u0))) + h8) - ((((((long) x7) * ((long) x1_2)) + (((long) x6) * ((long) x2_2))) + (((long) x5) * ((long) x3_2))) + (((long) x4) * ((long) x4)));
        int z0 = ((int) c) & M28;
        long d = ((((((((long) u7) * ((long) u1_2)) + (((long) u6) * ((long) u2_2))) + (((long) u5) * ((long) u3_2))) + (((long) u4) * ((long) u4))) + (((long) s0) * ((long) s0))) - f0) + h8;
        int z8 = ((int) d) & M28;
        long f1 = ((long) x1) * ((long) x0_2);
        long h1 = ((long) s1) * (((long) s0_2) & U32);
        long h9 = (((long) s7) * (((long) s2_2) & U32)) + (((long) s6) * (((long) s3_2) & U32)) + (((long) s5) * (((long) s4_2) & U32));
        long c2 = (c >>> 28) + (((f1 + (((long) u1) * ((long) u0_2))) + h9) - (((((long) x7) * ((long) x2_2)) + (((long) x6) * ((long) x3_2))) + (((long) x5) * ((long) x4_2))));
        int z1 = ((int) c2) & M28;
        long d2 = (d >>> 28) + (((((((long) u7) * ((long) u2_2)) + (((long) u6) * ((long) u3_2))) + (((long) u5) * ((long) u4_2))) + h1) - f1) + h9;
        int z9 = ((int) d2) & M28;
        long f2 = (((long) x2) * ((long) x0_2)) + (((long) x1) * ((long) x1));
        long h2 = (((long) s2) * (((long) s0_2) & U32)) + (((long) s1) * ((long) s1));
        long h10 = (((long) s7) * (((long) s3_2) & U32)) + (((long) s6) * (((long) s4_2) & U32)) + (((long) s5) * ((long) s5));
        long c3 = (c2 >>> 28) + (((f2 + ((((long) u2) * ((long) u0_2)) + (((long) u1) * ((long) u1)))) + h10) - (((((long) x7) * ((long) x3_2)) + (((long) x6) * ((long) x4_2))) + (((long) x5) * ((long) x5))));
        int z2 = ((int) c3) & M28;
        long d3 = (d2 >>> 28) + (((((((long) u7) * ((long) u3_2)) + (((long) u6) * ((long) u4_2))) + (((long) u5) * ((long) u5))) + h2) - f2) + h10;
        int z10 = ((int) d3) & M28;
        long f3 = (((long) x3) * ((long) x0_2)) + (((long) x2) * ((long) x1_2));
        long h3 = (((long) s3) * (((long) s0_2) & U32)) + (((long) s2) * (((long) s1_2) & U32));
        long h11 = (((long) s7) * (((long) s4_2) & U32)) + (((long) s6) * (((long) s5_2) & U32));
        long c4 = (c3 >>> 28) + (((f3 + ((((long) u3) * ((long) u0_2)) + (((long) u2) * ((long) u1_2)))) + h11) - ((((long) x7) * ((long) x4_2)) + (((long) x6) * ((long) x5_2))));
        int z3 = ((int) c4) & M28;
        long d4 = (d3 >>> 28) + ((((((long) u7) * ((long) u4_2)) + (((long) u6) * ((long) u5_2))) + h3) - f3) + h11;
        int z11 = ((int) d4) & M28;
        long f4 = (((long) x4) * ((long) x0_2)) + (((long) x3) * ((long) x1_2)) + (((long) x2) * ((long) x2));
        long h4 = (((long) s4) * (((long) s0_2) & U32)) + (((long) s3) * (((long) s1_2) & U32)) + (((long) s2) * ((long) s2));
        long h12 = (((long) s7) * (((long) s5_2) & U32)) + (((long) s6) * ((long) s6));
        long c5 = (c4 >>> 28) + (((f4 + (((((long) u4) * ((long) u0_2)) + (((long) u3) * ((long) u1_2))) + (((long) u2) * ((long) u2)))) + h12) - ((((long) x7) * ((long) x5_2)) + (((long) x6) * ((long) x6))));
        int z4 = ((int) c5) & M28;
        long d5 = (d4 >>> 28) + ((((((long) u7) * ((long) u5_2)) + (((long) u6) * ((long) u6))) + h4) - f4) + h12;
        int z12 = ((int) d5) & M28;
        long f5 = (((long) x5) * ((long) x0_2)) + (((long) x4) * ((long) x1_2)) + (((long) x3) * ((long) x2_2));
        long h5 = (((long) s5) * (((long) s0_2) & U32)) + (((long) s4) * (((long) s1_2) & U32)) + (((long) s3) * (((long) s2_2) & U32));
        long h13 = ((long) s7) * (((long) (s6 * 2)) & U32);
        long c6 = (c5 >>> 28) + (((f5 + (((((long) u5) * ((long) u0_2)) + (((long) u4) * ((long) u1_2))) + (((long) u3) * ((long) u2_2)))) + h13) - (((long) x7) * ((long) (x6 * 2))));
        int z5 = ((int) c6) & M28;
        long d6 = (d5 >>> 28) + (((((long) u7) * ((long) (u6 * 2))) + h5) - f5) + h13;
        int z13 = ((int) d6) & M28;
        long f6 = (((long) x6) * ((long) x0_2)) + (((long) x5) * ((long) x1_2)) + (((long) x4) * ((long) x2_2)) + (((long) x3) * ((long) x3));
        long h6 = (((long) s6) * (((long) s0_2) & U32)) + (((long) s5) * (((long) s1_2) & U32)) + (((long) s4) * (((long) s2_2) & U32)) + (((long) s3) * ((long) s3));
        long h14 = ((long) s7) * ((long) s7);
        long c7 = (c6 >>> 28) + (((f6 + ((((((long) u6) * ((long) u0_2)) + (((long) u5) * ((long) u1_2))) + (((long) u4) * ((long) u2_2))) + (((long) u3) * ((long) u3)))) + h14) - (((long) x7) * ((long) x7)));
        int z6 = ((int) c7) & M28;
        long d7 = (d6 >>> 28) + (((((long) u7) * ((long) u7)) + h6) - f6) + h14;
        int z14 = ((int) d7) & M28;
        long f7 = (((long) x7) * ((long) x0_2)) + (((long) x6) * ((long) x1_2)) + (((long) x5) * ((long) x2_2)) + (((long) x4) * ((long) x3_2));
        long h7 = (((long) s7) * (((long) s0_2) & U32)) + (((long) s6) * (((long) s1_2) & U32)) + (((long) s5) * (((long) s2_2) & U32)) + (((long) s4) * (((long) s3_2) & U32));
        long c8 = (c7 >>> 28) + f7 + (((long) u7) * ((long) u0_2)) + (((long) u6) * ((long) u1_2)) + (((long) u5) * ((long) u2_2)) + (((long) u4) * ((long) u3_2));
        int z7 = ((int) c8) & M28;
        long d8 = (d7 >>> 28) + (h7 - f7);
        int z15 = ((int) d8) & M28;
        long d9 = d8 >>> 28;
        long c9 = (c8 >>> 28) + d9 + ((long) z8);
        int z82 = ((int) c9) & M28;
        long d10 = d9 + ((long) z0);
        z[0] = ((int) d10) & M28;
        z[1] = z1 + ((int) (d10 >>> 28));
        z[2] = z2;
        z[3] = z3;
        z[4] = z4;
        z[5] = z5;
        z[6] = z6;
        z[7] = z7;
        z[8] = z82;
        z[9] = z9 + ((int) (c9 >>> 28));
        z[10] = z10;
        z[11] = z11;
        z[12] = z12;
        z[13] = z13;
        z[14] = z14;
        z[15] = z15;
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
        int[] u3v = create();
        int[] u5v3 = create();
        sqr(u, u3v);
        mul(u3v, v, u3v);
        sqr(u3v, u5v3);
        mul(u3v, u, u3v);
        mul(u5v3, u, u5v3);
        mul(u5v3, v, u5v3);
        int[] x = create();
        powPm3d4(u5v3, x);
        mul(x, u3v, x);
        int[] t = create();
        sqr(x, t);
        mul(t, v, t);
        sub(u, t, t);
        normalize(t);
        if (!isZeroVar(t)) {
            return false;
        }
        copy(x, 0, z, 0);
        return true;
    }

    public static void sub(int[] x, int[] y, int[] z) {
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
        int x10 = x[10];
        int x11 = x[11];
        int x12 = x[12];
        int x13 = x[13];
        int x14 = x[14];
        int x15 = x[15];
        int y0 = y[0];
        int y1 = y[1];
        int y2 = y[2];
        int y3 = y[3];
        int y4 = y[4];
        int y5 = y[5];
        int y6 = y[6];
        int y7 = y[7];
        int y8 = y[8];
        int y9 = y[9];
        int y10 = y[10];
        int y11 = y[11];
        int y12 = y[12];
        int y13 = y[13];
        int z1 = (536870910 + x1) - y1;
        int z5 = (536870910 + x5) - y5;
        int z9 = (536870910 + x9) - y9;
        int z13 = (536870910 + x13) - y13;
        int z15 = (536870910 + x15) - y[15];
        int z2 = ((536870910 + x2) - y2) + (z1 >>> 28);
        int z12 = z1 & M28;
        int z6 = ((536870910 + x6) - y6) + (z5 >>> 28);
        int z52 = z5 & M28;
        int z10 = ((536870910 + x10) - y10) + (z9 >>> 28);
        int z92 = z9 & M28;
        int z14 = ((536870910 + x14) - y[14]) + (z13 >>> 28);
        int z132 = z13 & M28;
        int z3 = ((536870910 + x3) - y3) + (z2 >>> 28);
        int z22 = z2 & M28;
        int z7 = ((536870910 + x7) - y7) + (z6 >>> 28);
        int z62 = z6 & M28;
        int z11 = ((536870910 + x11) - y11) + (z10 >>> 28);
        int z102 = z10 & M28;
        int z152 = z15 + (z14 >>> 28);
        int z142 = z14 & M28;
        int t = z152 >>> 28;
        int z153 = z152 & M28;
        int z0 = ((536870910 + x0) - y0) + t;
        int z4 = ((536870910 + x4) - y4) + (z3 >>> 28);
        int z32 = z3 & M28;
        int z8 = ((536870908 + x8) - y8) + t + (z7 >>> 28);
        int z72 = z7 & M28;
        int z122 = ((536870910 + x12) - y12) + (z11 >>> 28);
        int z112 = z11 & M28;
        int z16 = z12 + (z0 >>> 28);
        int z02 = z0 & M28;
        int z53 = z52 + (z4 >>> 28);
        int z42 = z4 & M28;
        int z93 = z92 + (z8 >>> 28);
        int z82 = z8 & M28;
        int z123 = z122 & M28;
        z[0] = z02;
        z[1] = z16;
        z[2] = z22;
        z[3] = z32;
        z[4] = z42;
        z[5] = z53;
        z[6] = z62;
        z[7] = z72;
        z[8] = z82;
        z[9] = z93;
        z[10] = z102;
        z[11] = z112;
        z[12] = z123;
        z[13] = z132 + (z122 >>> 28);
        z[14] = z142;
        z[15] = z153;
    }

    public static void subOne(int[] z) {
        int[] one = create();
        one[0] = 1;
        sub(z, one, z);
    }

    public static void zero(int[] z) {
        for (int i = 0; i < 16; i++) {
            z[i] = 0;
        }
    }
}
