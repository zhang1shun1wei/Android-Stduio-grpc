package com.mi.car.jsse.easysec.math.ec.custom.djb;

import com.mi.car.jsse.easysec.math.raw.Mod;
import com.mi.car.jsse.easysec.math.raw.Nat;
import com.mi.car.jsse.easysec.math.raw.Nat256;
import com.mi.car.jsse.easysec.util.Pack;
import java.math.BigInteger;
import java.security.SecureRandom;

public class Curve25519Field {
    private static final int P7 = Integer.MAX_VALUE;
    private static final long M = 4294967295L;
    static final int[] P = {-19, -1, -1, -1, -1, -1, -1, P7};
    private static final int[] PExt = {361, 0, 0, 0, 0, 0, 0, 0, -19, -1, -1, -1, -1, -1, -1, 1073741823};
    private static final int PInv = 19;

    public static void add(int[] x, int[] y, int[] z) {
        Nat256.add(x, y, z);
        if (Nat256.gte(z, P)) {
            subPFrom(z);
        }
    }

    public static void addExt(int[] xx, int[] yy, int[] zz) {
        Nat.add(16, xx, yy, zz);
        if (Nat.gte(16, zz, PExt)) {
            subPExtFrom(zz);
        }
    }

    public static void addOne(int[] x, int[] z) {
        Nat.inc(8, x, z);
        if (Nat256.gte(z, P)) {
            subPFrom(z);
        }
    }

    public static int[] fromBigInteger(BigInteger x) {
        int[] z = Nat256.fromBigInteger(x);
        while (Nat256.gte(z, P)) {
            Nat256.subFrom(P, z);
        }
        return z;
    }

    public static void half(int[] x, int[] z) {
        if ((x[0] & 1) == 0) {
            Nat.shiftDownBit(8, x, 0, z);
            return;
        }
        Nat256.add(x, P, z);
        Nat.shiftDownBit(8, z, 0);
    }

    public static void inv(int[] x, int[] z) {
        Mod.checkedModOddInverse(P, x, z);
    }

    public static int isZero(int[] x) {
        int d = 0;
        for (int i = 0; i < 8; i++) {
            d |= x[i];
        }
        return (((d >>> 1) | (d & 1)) - 1) >> 31;
    }

    public static void multiply(int[] x, int[] y, int[] z) {
        int[] tt = Nat256.createExt();
        Nat256.mul(x, y, tt);
        reduce(tt, z);
    }

    public static void multiplyAddToExt(int[] x, int[] y, int[] zz) {
        Nat256.mulAddTo(x, y, zz);
        if (Nat.gte(16, zz, PExt)) {
            subPExtFrom(zz);
        }
    }

    public static void negate(int[] x, int[] z) {
        if (isZero(x) != 0) {
            Nat256.sub(P, P, z);
        } else {
            Nat256.sub(P, x, z);
        }
    }

    public static void random(SecureRandom r, int[] z) {
        byte[] bb = new byte[32];
        do {
            r.nextBytes(bb);
            Pack.littleEndianToInt(bb, 0, z, 0, 8);
            z[7] = z[7] & P7;
        } while (Nat.lessThan(8, z, P) == 0);
    }

    public static void randomMult(SecureRandom r, int[] z) {
        do {
            random(r, z);
        } while (isZero(z) != 0);
    }

    public static void reduce(int[] xx, int[] z) {
        int xx07 = xx[7];
        Nat.shiftUpBit(8, xx, 8, xx07, z, 0);
        int z7 = z[7];
        z[7] = (z7 & P7) + Nat.addWordTo(7, ((Nat256.mulByWordAddTo(19, xx, z) << 1) + ((z7 >>> 31) - (xx07 >>> 31))) * 19, z);
        if (Nat256.gte(z, P)) {
            subPFrom(z);
        }
    }

    public static void reduce27(int x, int[] z) {
        int z7 = z[7];
        z[7] = (z7 & P7) + Nat.addWordTo(7, ((x << 1) | (z7 >>> 31)) * 19, z);
        if (Nat256.gte(z, P)) {
            subPFrom(z);
        }
    }

    public static void square(int[] x, int[] z) {
        int[] tt = Nat256.createExt();
        Nat256.square(x, tt);
        reduce(tt, z);
    }

    public static void squareN(int[] x, int n, int[] z) {
        int[] tt = Nat256.createExt();
        Nat256.square(x, tt);
        reduce(tt, z);
        while (true) {
            n--;
            if (n > 0) {
                Nat256.square(z, tt);
                reduce(tt, z);
            } else {
                return;
            }
        }
    }

    public static void subtract(int[] x, int[] y, int[] z) {
        if (Nat256.sub(x, y, z) != 0) {
            addPTo(z);
        }
    }

    public static void subtractExt(int[] xx, int[] yy, int[] zz) {
        if (Nat.sub(16, xx, yy, zz) != 0) {
            addPExtTo(zz);
        }
    }

    public static void twice(int[] x, int[] z) {
        Nat.shiftUpBit(8, x, 0, z);
        if (Nat256.gte(z, P)) {
            subPFrom(z);
        }
    }

    private static int addPTo(int[] z) {
        long c = (((long) z[0]) & M) - 19;
        z[0] = (int) c;
        long c2 = c >> 32;
        if (c2 != 0) {
            c2 = (long) Nat.decAt(7, z, 1);
        }
        long c3 = c2 + (((long) z[7]) & M) + 2147483648L;
        z[7] = (int) c3;
        return (int) (c3 >> 32);
    }

    private static int addPExtTo(int[] zz) {
        long c = (((long) zz[0]) & M) + (((long) PExt[0]) & M);
        zz[0] = (int) c;
        long c2 = c >> 32;
        if (c2 != 0) {
            c2 = (long) Nat.incAt(8, zz, 1);
        }
        long c3 = c2 + ((((long) zz[8]) & M) - 19);
        zz[8] = (int) c3;
        long c4 = c3 >> 32;
        if (c4 != 0) {
            c4 = (long) Nat.decAt(15, zz, 9);
        }
        long c5 = c4 + (((long) zz[15]) & M) + (((long) (PExt[15] + 1)) & M);
        zz[15] = (int) c5;
        return (int) (c5 >> 32);
    }

    private static int subPFrom(int[] z) {
        long c = (((long) z[0]) & M) + 19;
        z[0] = (int) c;
        long c2 = c >> 32;
        if (c2 != 0) {
            c2 = (long) Nat.incAt(7, z, 1);
        }
        long c3 = c2 + ((((long) z[7]) & M) - 2147483648L);
        z[7] = (int) c3;
        return (int) (c3 >> 32);
    }

    private static int subPExtFrom(int[] zz) {
        long c = (((long) zz[0]) & M) - (((long) PExt[0]) & M);
        zz[0] = (int) c;
        long c2 = c >> 32;
        if (c2 != 0) {
            c2 = (long) Nat.decAt(8, zz, 1);
        }
        long c3 = c2 + (((long) zz[8]) & M) + 19;
        zz[8] = (int) c3;
        long c4 = c3 >> 32;
        if (c4 != 0) {
            c4 = (long) Nat.incAt(15, zz, 9);
        }
        long c5 = c4 + ((((long) zz[15]) & M) - (((long) (PExt[15] + 1)) & M));
        zz[15] = (int) c5;
        return (int) (c5 >> 32);
    }
}
