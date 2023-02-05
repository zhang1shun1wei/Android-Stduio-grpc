package com.mi.car.jsse.easysec.math.ec.custom.sec;

import com.mi.car.jsse.easysec.math.raw.Mod;
import com.mi.car.jsse.easysec.math.raw.Nat;
import com.mi.car.jsse.easysec.math.raw.Nat160;
import com.mi.car.jsse.easysec.util.Pack;
import java.math.BigInteger;
import java.security.SecureRandom;

public class SecP160R2Field {
    static final int[] P = {-21389, -2, -1, -1, -1};
    private static final int P4 = -1;
    private static final int[] PExt = {457489321, 42778, 1, 0, 0, -42778, -3, -1, -1, -1};
    private static final int PExt9 = -1;
    private static final int[] PExtInv = {-457489321, -42779, -2, -1, -1, 42777, 2};
    private static final int PInv33 = 21389;

    public static void add(int[] x, int[] y, int[] z) {
        if (Nat160.add(x, y, z) != 0 || (z[4] == -1 && Nat160.gte(z, P))) {
            Nat.add33To(5, PInv33, z);
        }
    }

    public static void addExt(int[] xx, int[] yy, int[] zz) {
        if ((Nat.add(10, xx, yy, zz) != 0 || (zz[9] == -1 && Nat.gte(10, zz, PExt))) && Nat.addTo(PExtInv.length, PExtInv, zz) != 0) {
            Nat.incAt(10, zz, PExtInv.length);
        }
    }

    public static void addOne(int[] x, int[] z) {
        if (Nat.inc(5, x, z) != 0 || (z[4] == -1 && Nat160.gte(z, P))) {
            Nat.add33To(5, PInv33, z);
        }
    }

    public static int[] fromBigInteger(BigInteger x) {
        int[] z = Nat160.fromBigInteger(x);
        if (z[4] == -1 && Nat160.gte(z, P)) {
            Nat160.subFrom(P, z);
        }
        return z;
    }

    public static void half(int[] x, int[] z) {
        if ((x[0] & 1) == 0) {
            Nat.shiftDownBit(5, x, 0, z);
        } else {
            Nat.shiftDownBit(5, z, Nat160.add(x, P, z));
        }
    }

    public static void inv(int[] x, int[] z) {
        Mod.checkedModOddInverse(P, x, z);
    }

    public static int isZero(int[] x) {
        int d = 0;
        for (int i = 0; i < 5; i++) {
            d |= x[i];
        }
        return (((d >>> 1) | (d & 1)) - 1) >> 31;
    }

    public static void multiply(int[] x, int[] y, int[] z) {
        int[] tt = Nat160.createExt();
        Nat160.mul(x, y, tt);
        reduce(tt, z);
    }

    public static void multiplyAddToExt(int[] x, int[] y, int[] zz) {
        if ((Nat160.mulAddTo(x, y, zz) != 0 || (zz[9] == -1 && Nat.gte(10, zz, PExt))) && Nat.addTo(PExtInv.length, PExtInv, zz) != 0) {
            Nat.incAt(10, zz, PExtInv.length);
        }
    }

    public static void negate(int[] x, int[] z) {
        if (isZero(x) != 0) {
            Nat160.sub(P, P, z);
        } else {
            Nat160.sub(P, x, z);
        }
    }

    public static void random(SecureRandom r, int[] z) {
        byte[] bb = new byte[20];
        do {
            r.nextBytes(bb);
            Pack.littleEndianToInt(bb, 0, z, 0, 5);
        } while (Nat.lessThan(5, z, P) == 0);
    }

    public static void randomMult(SecureRandom r, int[] z) {
        do {
            random(r, z);
        } while (isZero(z) != 0);
    }

    public static void reduce(int[] xx, int[] z) {
        if (Nat160.mul33DWordAdd(PInv33, Nat160.mul33Add(PInv33, xx, 5, xx, 0, z, 0), z, 0) != 0 || (z[4] == -1 && Nat160.gte(z, P))) {
            Nat.add33To(5, PInv33, z);
        }
    }

    public static void reduce32(int x, int[] z) {
        if ((x != 0 && Nat160.mul33WordAdd(PInv33, x, z, 0) != 0) || (z[4] == -1 && Nat160.gte(z, P))) {
            Nat.add33To(5, PInv33, z);
        }
    }

    public static void square(int[] x, int[] z) {
        int[] tt = Nat160.createExt();
        Nat160.square(x, tt);
        reduce(tt, z);
    }

    public static void squareN(int[] x, int n, int[] z) {
        int[] tt = Nat160.createExt();
        Nat160.square(x, tt);
        reduce(tt, z);
        while (true) {
            n--;
            if (n > 0) {
                Nat160.square(z, tt);
                reduce(tt, z);
            } else {
                return;
            }
        }
    }

    public static void subtract(int[] x, int[] y, int[] z) {
        if (Nat160.sub(x, y, z) != 0) {
            Nat.sub33From(5, PInv33, z);
        }
    }

    public static void subtractExt(int[] xx, int[] yy, int[] zz) {
        if (Nat.sub(10, xx, yy, zz) != 0 && Nat.subFrom(PExtInv.length, PExtInv, zz) != 0) {
            Nat.decAt(10, zz, PExtInv.length);
        }
    }

    public static void twice(int[] x, int[] z) {
        if (Nat.shiftUpBit(5, x, 0, z) != 0 || (z[4] == -1 && Nat160.gte(z, P))) {
            Nat.add33To(5, PInv33, z);
        }
    }
}
