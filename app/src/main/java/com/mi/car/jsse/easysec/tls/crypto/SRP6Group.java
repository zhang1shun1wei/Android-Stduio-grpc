package com.mi.car.jsse.easysec.tls.crypto;

import java.math.BigInteger;

public class SRP6Group {
    private BigInteger N;
    private BigInteger g;

    public SRP6Group(BigInteger N2, BigInteger g2) {
        this.N = N2;
        this.g = g2;
    }

    public BigInteger getG() {
        return this.g;
    }

    public BigInteger getN() {
        return this.N;
    }
}
