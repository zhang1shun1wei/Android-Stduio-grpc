package com.mi.car.jsse.easysec.math.ec.custom.sec;

import com.mi.car.jsse.easysec.math.raw.Mod;
import com.mi.car.jsse.easysec.math.raw.Nat;
import com.mi.car.jsse.easysec.math.raw.Nat512;
import com.mi.car.jsse.easysec.util.Pack;
import java.math.BigInteger;
import java.security.SecureRandom;

public class SecP521R1Field {
    private static final int P16 = 511;
    static final int[] P = {-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, P16};

    public static void add(int[] x, int[] y, int[] z) {
        int c = Nat.add(16, x, y, z) + x[16] + y[16];
        if (c > P16 || (c == P16 && Nat.eq(16, z, P))) {
            c = (c + Nat.inc(16, z)) & P16;
        }
        z[16] = c;
    }

    public static void addOne(int[] x, int[] z) {
        int c = Nat.inc(16, x, z) + x[16];
        if (c > P16 || (c == P16 && Nat.eq(16, z, P))) {
            c = (c + Nat.inc(16, z)) & P16;
        }
        z[16] = c;
    }

    public static int[] fromBigInteger(BigInteger x) {
        int[] z = Nat.fromBigInteger(521, x);
        if (Nat.eq(17, z, P)) {
            Nat.zero(17, z);
        }
        return z;
    }

    public static void half(int[] x, int[] z) {
        int x16 = x[16];
        z[16] = (x16 >>> 1) | (Nat.shiftDownBit(16, x, x16, z) >>> 23);
    }

    public static void inv(int[] x, int[] z) {
        Mod.checkedModOddInverse(P, x, z);
    }

    public static int isZero(int[] x) {
        int d = 0;
        for (int i = 0; i < 17; i++) {
            d |= x[i];
        }
        return (((d >>> 1) | (d & 1)) - 1) >> 31;
    }

    public static void multiply(int[] x, int[] y, int[] z) {
        int[] tt = Nat.create(33);
        implMultiply(x, y, tt);
        reduce(tt, z);
    }

    public static void multiply(int[] x, int[] y, int[] z, int[] tt) {
        implMultiply(x, y, tt);
        reduce(tt, z);
    }

    public static void negate(int[] x, int[] z) {
        if (isZero(x) != 0) {
            Nat.sub(17, P, P, z);
        } else {
            Nat.sub(17, P, x, z);
        }
    }

    public static void random(SecureRandom r, int[] z) {
        byte[] bb = new byte[68];
        do {
            r.nextBytes(bb);
            Pack.littleEndianToInt(bb, 0, z, 0, 17);
            z[16] = z[16] & P16;
        } while (Nat.lessThan(17, z, P) == 0);
    }

    public static void randomMult(SecureRandom r, int[] z) {
        do {
            random(r, z);
        } while (isZero(z) != 0);
    }

    public static void reduce(int[] xx, int[] z) {
        int xx32 = xx[32];
        int c = (Nat.shiftDownBits(16, xx, 16, 9, xx32, z, 0) >>> 23) + (xx32 >>> 9) + Nat.addTo(16, xx, z);
        if (c > P16 || (c == P16 && Nat.eq(16, z, P))) {
            c = (c + Nat.inc(16, z)) & P16;
        }
        z[16] = c;
    }

    public static void reduce23(int[] z) {
        int z16 = z[16];
        int c = Nat.addWordTo(16, z16 >>> 9, z) + (z16 & P16);
        if (c > P16 || (c == P16 && Nat.eq(16, z, P))) {
            c = (c + Nat.inc(16, z)) & P16;
        }
        z[16] = c;
    }

    public static void square(int[] x, int[] z) {
        int[] tt = Nat.create(33);
        implSquare(x, tt);
        reduce(tt, z);
    }

    public static void square(int[] x, int[] z, int[] tt) {
        implSquare(x, tt);
        reduce(tt, z);
    }

    public static void squareN(int[] x, int n, int[] z) {
        int[] tt = Nat.create(33);
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

    public static void squareN(int[] x, int n, int[] z, int[] tt) {
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

    public static void subtract(int[] x, int[] y, int[] z) {
        int c = (Nat.sub(16, x, y, z) + x[16]) - y[16];
        if (c < 0) {
            c = (c + Nat.dec(16, z)) & P16;
        }
        z[16] = c;
    }

    public static void twice(int[] x, int[] z) {
        int x16 = x[16];
        z[16] = (Nat.shiftUpBit(16, x, x16 << 23, z) | (x16 << 1)) & P16;
    }

    protected static void implMultiply(int[] x, int[] y, int[] zz) {
        Nat512.mul(x, y, zz);
        int x16 = x[16];
        int y16 = y[16];
        zz[32] = Nat.mul31BothAdd(16, x16, y, y16, x, zz, 16) + (x16 * y16);
    }

    protected static void implSquare(int[] x, int[] zz) {
        Nat512.square(x, zz);
        int x16 = x[16];
        zz[32] = Nat.mulWordAddTo(16, x16 << 1, x, 0, zz, 16) + (x16 * x16);
    }
}
