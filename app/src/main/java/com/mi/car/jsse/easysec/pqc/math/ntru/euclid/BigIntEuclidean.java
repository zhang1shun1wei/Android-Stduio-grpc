package com.mi.car.jsse.easysec.pqc.math.ntru.euclid;

import java.math.BigInteger;

public class BigIntEuclidean {
    public BigInteger gcd;
    public BigInteger x;
    public BigInteger y;

    private BigIntEuclidean() {
    }

    public static BigIntEuclidean calculate(BigInteger a, BigInteger b) {
        BigInteger x2 = BigInteger.ZERO;
        BigInteger lastx = BigInteger.ONE;
        BigInteger y2 = BigInteger.ONE;
        BigInteger lasty = BigInteger.ZERO;
        while (!b.equals(BigInteger.ZERO)) {
            BigInteger[] quotientAndRemainder = a.divideAndRemainder(b);
            BigInteger quotient = quotientAndRemainder[0];
            a = b;
            b = quotientAndRemainder[1];
            x2 = lastx.subtract(quotient.multiply(x2));
            lastx = x2;
            y2 = lasty.subtract(quotient.multiply(y2));
            lasty = y2;
        }
        BigIntEuclidean result = new BigIntEuclidean();
        result.x = lastx;
        result.y = lasty;
        result.gcd = a;
        return result;
    }
}
