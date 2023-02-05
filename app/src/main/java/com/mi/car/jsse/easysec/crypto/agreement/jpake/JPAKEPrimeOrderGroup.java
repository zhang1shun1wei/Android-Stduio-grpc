package com.mi.car.jsse.easysec.crypto.agreement.jpake;

import java.math.BigInteger;

public class JPAKEPrimeOrderGroup {
    private final BigInteger g;
    private final BigInteger p;
    private final BigInteger q;

    public JPAKEPrimeOrderGroup(BigInteger p2, BigInteger q2, BigInteger g2) {
        this(p2, q2, g2, false);
    }

    JPAKEPrimeOrderGroup(BigInteger p2, BigInteger q2, BigInteger g2, boolean skipChecks) {
        JPAKEUtil.validateNotNull(p2, "p");
        JPAKEUtil.validateNotNull(q2, "q");
        JPAKEUtil.validateNotNull(g2, "g");
        if (!skipChecks) {
            if (!p2.subtract(JPAKEUtil.ONE).mod(q2).equals(JPAKEUtil.ZERO)) {
                throw new IllegalArgumentException("p-1 must be evenly divisible by q");
            } else if (g2.compareTo(BigInteger.valueOf(2)) == -1 || g2.compareTo(p2.subtract(JPAKEUtil.ONE)) == 1) {
                throw new IllegalArgumentException("g must be in [2, p-1]");
            } else if (!g2.modPow(q2, p2).equals(JPAKEUtil.ONE)) {
                throw new IllegalArgumentException("g^q mod p must equal 1");
            } else if (!p2.isProbablePrime(20)) {
                throw new IllegalArgumentException("p must be prime");
            } else if (!q2.isProbablePrime(20)) {
                throw new IllegalArgumentException("q must be prime");
            }
        }
        this.p = p2;
        this.q = q2;
        this.g = g2;
    }

    public BigInteger getP() {
        return this.p;
    }

    public BigInteger getQ() {
        return this.q;
    }

    public BigInteger getG() {
        return this.g;
    }
}
