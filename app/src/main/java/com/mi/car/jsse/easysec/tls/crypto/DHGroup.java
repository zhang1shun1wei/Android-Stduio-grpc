package com.mi.car.jsse.easysec.tls.crypto;

import java.math.BigInteger;

public class DHGroup {
    private final BigInteger g;
    private final int l;
    private final BigInteger p;
    private final BigInteger q;

    public DHGroup(BigInteger p2, BigInteger q2, BigInteger g2, int l2) {
        this.p = p2;
        this.g = g2;
        this.q = q2;
        this.l = l2;
    }

    public BigInteger getG() {
        return this.g;
    }

    public int getL() {
        return this.l;
    }

    public BigInteger getP() {
        return this.p;
    }

    public BigInteger getQ() {
        return this.q;
    }
}
