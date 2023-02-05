package com.mi.car.jsse.easysec.math.ec.custom.sec;

import com.mi.car.jsse.easysec.math.raw.Mod;
import com.mi.car.jsse.easysec.math.raw.Nat;
import com.mi.car.jsse.easysec.math.raw.Nat128;
import com.mi.car.jsse.easysec.math.raw.Nat256;
import com.mi.car.jsse.easysec.util.Pack;
import java.math.BigInteger;
import java.security.SecureRandom;

public class SecP128R1Field {
    private static final long M = 4294967295L;
    static final int[] P = {-1, -1, -1, -3};
    private static final int P3s1 = 2147483646;
    private static final int[] PExt = {1, 0, 0, 4, -2, -1, 3, -4};
    private static final int PExt7s1 = 2147483646;
    private static final int[] PExtInv = {-1, -1, -1, -5, 1, 0, -4, 3};

    public static void add(int[] x, int[] y, int[] z) {
        if (Nat128.add(x, y, z) != 0 || ((z[3] >>> 1) >= 2147483646 && Nat128.gte(z, P))) {
            addPInvTo(z);
        }
    }

    public static void addExt(int[] xx, int[] yy, int[] zz) {
        if (Nat256.add(xx, yy, zz) != 0 || ((zz[7] >>> 1) >= 2147483646 && Nat256.gte(zz, PExt))) {
            Nat.addTo(PExtInv.length, PExtInv, zz);
        }
    }

    public static void addOne(int[] x, int[] z) {
        if (Nat.inc(4, x, z) != 0 || ((z[3] >>> 1) >= 2147483646 && Nat128.gte(z, P))) {
            addPInvTo(z);
        }
    }

    public static int[] fromBigInteger(BigInteger x) {
        int[] z = Nat128.fromBigInteger(x);
        if ((z[3] >>> 1) >= 2147483646 && Nat128.gte(z, P)) {
            Nat128.subFrom(P, z);
        }
        return z;
    }

    public static void half(int[] x, int[] z) {
        if ((x[0] & 1) == 0) {
            Nat.shiftDownBit(4, x, 0, z);
        } else {
            Nat.shiftDownBit(4, z, Nat128.add(x, P, z));
        }
    }

    public static void inv(int[] x, int[] z) {
        Mod.checkedModOddInverse(P, x, z);
    }

    public static int isZero(int[] x) {
        int d = 0;
        for (int i = 0; i < 4; i++) {
            d |= x[i];
        }
        return (((d >>> 1) | (d & 1)) - 1) >> 31;
    }

    public static void multiply(int[] x, int[] y, int[] z) {
        int[] tt = Nat128.createExt();
        Nat128.mul(x, y, tt);
        reduce(tt, z);
    }

    public static void multiplyAddToExt(int[] x, int[] y, int[] zz) {
        if (Nat128.mulAddTo(x, y, zz) != 0 || ((zz[7] >>> 1) >= 2147483646 && Nat256.gte(zz, PExt))) {
            Nat.addTo(PExtInv.length, PExtInv, zz);
        }
    }

    public static void negate(int[] x, int[] z) {
        if (isZero(x) != 0) {
            Nat128.sub(P, P, z);
        } else {
            Nat128.sub(P, x, z);
        }
    }

    public static void random(SecureRandom r, int[] z) {
        byte[] bb = new byte[16];
        do {
            r.nextBytes(bb);
            Pack.littleEndianToInt(bb, 0, z, 0, 4);
        } while (Nat.lessThan(4, z, P) == 0);
    }

    public static void randomMult(SecureRandom r, int[] z) {
        do {
            random(r, z);
        } while (isZero(z) != 0);
    }

    public static void reduce(int[] xx, int[] z) {
        long x0 = ((long) xx[0]) & M;
        long x1 = ((long) xx[1]) & M;
        long x2 = ((long) xx[2]) & M;
        long x3 = ((long) xx[3]) & M;
        long x4 = ((long) xx[4]) & M;
        long x5 = ((long) xx[5]) & M;
        long x6 = ((long) xx[6]) & M;
        long x7 = ((long) xx[7]) & M;
        long x62 = x6 + (x7 << 1);
        long x52 = x5 + (x62 << 1);
        long x42 = x4 + (x52 << 1);
        long x02 = x0 + x42;
        z[0] = (int) x02;
        long x12 = x1 + x52 + (x02 >>> 32);
        z[1] = (int) x12;
        long x22 = x2 + x62 + (x12 >>> 32);
        z[2] = (int) x22;
        long x32 = x3 + x7 + (x42 << 1) + (x22 >>> 32);
        z[3] = (int) x32;
        reduce32((int) (x32 >>> 32), z);
    }

    public static void reduce32(int x, int[] z) {
        while (x != 0) {
            long x4 = ((long) x) & M;
            long c = (((long) z[0]) & M) + x4;
            z[0] = (int) c;
            long c2 = c >> 32;
            if (c2 != 0) {
                long c3 = c2 + (((long) z[1]) & M);
                z[1] = (int) c3;
                long c4 = (c3 >> 32) + (((long) z[2]) & M);
                z[2] = (int) c4;
                c2 = c4 >> 32;
            }
            long c5 = c2 + (((long) z[3]) & M) + (x4 << 1);
            z[3] = (int) c5;
            x = (int) (c5 >> 32);
        }
        if ((z[3] >>> 1) >= 2147483646 && Nat128.gte(z, P)) {
            addPInvTo(z);
        }
    }

    public static void square(int[] x, int[] z) {
        int[] tt = Nat128.createExt();
        Nat128.square(x, tt);
        reduce(tt, z);
    }

    public static void squareN(int[] x, int n, int[] z) {
        int[] tt = Nat128.createExt();
        Nat128.square(x, tt);
        reduce(tt, z);
        while (true) {
            n--;
            if (n > 0) {
                Nat128.square(z, tt);
                reduce(tt, z);
            } else {
                return;
            }
        }
    }

    public static void subtract(int[] x, int[] y, int[] z) {
        if (Nat128.sub(x, y, z) != 0) {
            subPInvFrom(z);
        }
    }

    public static void subtractExt(int[] xx, int[] yy, int[] zz) {
        if (Nat.sub(10, xx, yy, zz) != 0) {
            Nat.subFrom(PExtInv.length, PExtInv, zz);
        }
    }

    public static void twice(int[] x, int[] z) {
        if (Nat.shiftUpBit(4, x, 0, z) != 0 || ((z[3] >>> 1) >= 2147483646 && Nat128.gte(z, P))) {
            addPInvTo(z);
        }
    }

    private static void addPInvTo(int[] z) {
        long c = (((long) z[0]) & M) + 1;
        z[0] = (int) c;
        long c2 = c >> 32;
        if (c2 != 0) {
            long c3 = c2 + (((long) z[1]) & M);
            z[1] = (int) c3;
            long c4 = (c3 >> 32) + (((long) z[2]) & M);
            z[2] = (int) c4;
            c2 = c4 >> 32;
        }
        z[3] = (int) (c2 + (((long) z[3]) & M) + 2);
    }

    private static void subPInvFrom(int[] z) {
        long c = (((long) z[0]) & M) - 1;
        z[0] = (int) c;
        long c2 = c >> 32;
        if (c2 != 0) {
            long c3 = c2 + (((long) z[1]) & M);
            z[1] = (int) c3;
            long c4 = (c3 >> 32) + (((long) z[2]) & M);
            z[2] = (int) c4;
            c2 = c4 >> 32;
        }
        z[3] = (int) (c2 + ((((long) z[3]) & M) - 2));
    }
}
