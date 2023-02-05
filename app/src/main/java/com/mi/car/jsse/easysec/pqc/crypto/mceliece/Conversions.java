package com.mi.car.jsse.easysec.pqc.crypto.mceliece;

import com.mi.car.jsse.easysec.pqc.math.linearalgebra.BigIntUtils;
import com.mi.car.jsse.easysec.pqc.math.linearalgebra.GF2Vector;
import com.mi.car.jsse.easysec.pqc.math.linearalgebra.IntegerFunctions;
import java.math.BigInteger;

final class Conversions {
    private static final BigInteger ONE = BigInteger.valueOf(1);
    private static final BigInteger ZERO = BigInteger.valueOf(0);

    private Conversions() {
    }

    public static GF2Vector encode(int n, int t, byte[] m) {
        if (n < t) {
            throw new IllegalArgumentException("n < t");
        }
        BigInteger c = IntegerFunctions.binomial(n, t);
        BigInteger i = new BigInteger(1, m);
        if (i.compareTo(c) >= 0) {
            throw new IllegalArgumentException("Encoded number too large.");
        }
        GF2Vector result = new GF2Vector(n);
        int nn = n;
        int tt = t;
        for (int j = 0; j < n; j++) {
            c = c.multiply(BigInteger.valueOf((long) (nn - tt))).divide(BigInteger.valueOf((long) nn));
            nn--;
            if (c.compareTo(i) <= 0) {
                result.setBit(j);
                i = i.subtract(c);
                tt--;
                if (nn == tt) {
                    c = ONE;
                } else {
                    c = c.multiply(BigInteger.valueOf((long) (tt + 1))).divide(BigInteger.valueOf((long) (nn - tt)));
                }
            }
        }
        return result;
    }

    public static byte[] decode(int n, int t, GF2Vector vec) {
        if (vec.getLength() == n && vec.getHammingWeight() == t) {
            int[] vecArray = vec.getVecArray();
            BigInteger bc = IntegerFunctions.binomial(n, t);
            BigInteger d = ZERO;
            int nn = n;
            int tt = t;
            for (int i = 0; i < n; i++) {
                bc = bc.multiply(BigInteger.valueOf((long) (nn - tt))).divide(BigInteger.valueOf((long) nn));
                nn--;
                if ((vecArray[i >> 5] & (1 << (i & 31))) != 0) {
                    d = d.add(bc);
                    tt--;
                    if (nn == tt) {
                        bc = ONE;
                    } else {
                        bc = bc.multiply(BigInteger.valueOf((long) (tt + 1))).divide(BigInteger.valueOf((long) (nn - tt)));
                    }
                }
            }
            return BigIntUtils.toMinimalByteArray(d);
        }
        throw new IllegalArgumentException("vector has wrong length or hamming weight");
    }

    public static byte[] signConversion(int n, int t, byte[] m) {
        if (n < t) {
            throw new IllegalArgumentException("n < t");
        }
        BigInteger bc = IntegerFunctions.binomial(n, t);
        int s = bc.bitLength() - 1;
        int sq = s >> 3;
        int sr = s & 7;
        if (sr == 0) {
            sq--;
            sr = 8;
        }
        int nq = n >> 3;
        int nr = n & 7;
        if (nr == 0) {
            nq--;
            nr = 8;
        }
        byte[] data = new byte[(nq + 1)];
        if (m.length < data.length) {
            System.arraycopy(m, 0, data, 0, m.length);
            for (int i = m.length; i < data.length; i++) {
                data[i] = 0;
            }
        } else {
            System.arraycopy(m, 0, data, 0, nq);
            data[nq] = (byte) (m[nq] & ((1 << nr) - 1));
        }
        BigInteger d = ZERO;
        int nn = n;
        int tt = t;
        for (int i2 = 0; i2 < n; i2++) {
            bc = bc.multiply(new BigInteger(Integer.toString(nn - tt))).divide(new BigInteger(Integer.toString(nn)));
            nn--;
            if (((byte) (data[i2 >>> 3] & (1 << (i2 & 7)))) != 0) {
                d = d.add(bc);
                tt--;
                if (nn == tt) {
                    bc = ONE;
                } else {
                    bc = bc.multiply(new BigInteger(Integer.toString(tt + 1))).divide(new BigInteger(Integer.toString(nn - tt)));
                }
            }
        }
        byte[] result = new byte[(sq + 1)];
        byte[] help = d.toByteArray();
        if (help.length < result.length) {
            System.arraycopy(help, 0, result, 0, help.length);
            for (int i3 = help.length; i3 < result.length; i3++) {
                result[i3] = 0;
            }
        } else {
            System.arraycopy(help, 0, result, 0, sq);
            result[sq] = (byte) (((1 << sr) - 1) & help[sq]);
        }
        return result;
    }
}
