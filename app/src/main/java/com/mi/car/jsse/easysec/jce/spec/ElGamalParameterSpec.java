package com.mi.car.jsse.easysec.jce.spec;

import java.math.BigInteger;
import java.security.spec.AlgorithmParameterSpec;

public class ElGamalParameterSpec implements AlgorithmParameterSpec {
    private BigInteger g;
    private BigInteger p;

    public ElGamalParameterSpec(BigInteger p2, BigInteger g2) {
        this.p = p2;
        this.g = g2;
    }

    public BigInteger getP() {
        return this.p;
    }

    public BigInteger getG() {
        return this.g;
    }
}
