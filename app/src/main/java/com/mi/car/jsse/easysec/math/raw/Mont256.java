package com.mi.car.jsse.easysec.math.raw;

public abstract class Mont256 {
    private static final long M = 4294967295L;

    public static int inverse32(int x) {
        int z = x * (2 - (x * x));
        int z2 = z * (2 - (x * z));
        int z3 = z2 * (2 - (x * z2));
        return z3 * (2 - (x * z3));
    }

    public static void multAdd(int[] x, int[] y, int[] z, int[] m, int mInv32) {
        int z_8 = 0;
        long y_0 = ((long) y[0]) & M;
        for (int i = 0; i < 8; i++) {
            long z_0 = ((long) z[0]) & M;
            long x_i = ((long) x[i]) & M;
            long prod1 = x_i * y_0;
            long carry = (M & prod1) + z_0;
            long t = ((long) (((int) carry) * mInv32)) & M;
            long prod2 = t * (((long) m[0]) & M);
            long carry2 = ((carry + (M & prod2)) >>> 32) + (prod1 >>> 32) + (prod2 >>> 32);
            for (int j = 1; j < 8; j++) {
                long prod12 = x_i * (((long) y[j]) & M);
                long prod22 = t * (((long) m[j]) & M);
                long carry3 = carry2 + (M & prod12) + (M & prod22) + (((long) z[j]) & M);
                z[j - 1] = (int) carry3;
                carry2 = (carry3 >>> 32) + (prod12 >>> 32) + (prod22 >>> 32);
            }
            long carry4 = carry2 + (((long) z_8) & M);
            z[7] = (int) carry4;
            z_8 = (int) (carry4 >>> 32);
        }
        if (z_8 != 0 || Nat256.gte(z, m)) {
            Nat256.sub(z, m, z);
        }
    }

    public static void multAddXF(int[] x, int[] y, int[] z, int[] m) {
        int z_8 = 0;
        long y_0 = ((long) y[0]) & M;
        for (int i = 0; i < 8; i++) {
            long x_i = ((long) x[i]) & M;
            long carry = (x_i * y_0) + (((long) z[0]) & M);
            long t = carry & M;
            long carry2 = (carry >>> 32) + t;
            for (int j = 1; j < 8; j++) {
                long prod1 = x_i * (((long) y[j]) & M);
                long prod2 = t * (((long) m[j]) & M);
                long carry3 = carry2 + (M & prod1) + (M & prod2) + (((long) z[j]) & M);
                z[j - 1] = (int) carry3;
                carry2 = (carry3 >>> 32) + (prod1 >>> 32) + (prod2 >>> 32);
            }
            long carry4 = carry2 + (((long) z_8) & M);
            z[7] = (int) carry4;
            z_8 = (int) (carry4 >>> 32);
        }
        if (z_8 != 0 || Nat256.gte(z, m)) {
            Nat256.sub(z, m, z);
        }
    }

    public static void reduce(int[] z, int[] m, int mInv32) {
        for (int i = 0; i < 8; i++) {
            int z_0 = z[0];
            long t = ((long) (z_0 * mInv32)) & M;
            long carry = (((((long) m[0]) & M) * t) + (((long) z_0) & M)) >>> 32;
            for (int j = 1; j < 8; j++) {
                long carry2 = carry + ((((long) m[j]) & M) * t) + (((long) z[j]) & M);
                z[j - 1] = (int) carry2;
                carry = carry2 >>> 32;
            }
            z[7] = (int) carry;
        }
        if (Nat256.gte(z, m)) {
            Nat256.sub(z, m, z);
        }
    }

    public static void reduceXF(int[] z, int[] m) {
        for (int i = 0; i < 8; i++) {
            long t = ((long) z[0]) & M;
            long carry = t;
            for (int j = 1; j < 8; j++) {
                long carry2 = carry + ((((long) m[j]) & M) * t) + (((long) z[j]) & M);
                z[j - 1] = (int) carry2;
                carry = carry2 >>> 32;
            }
            z[7] = (int) carry;
        }
        if (Nat256.gte(z, m)) {
            Nat256.sub(z, m, z);
        }
    }
}
