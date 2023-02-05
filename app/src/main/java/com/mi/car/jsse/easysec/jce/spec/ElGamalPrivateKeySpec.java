package com.mi.car.jsse.easysec.jce.spec;

import java.math.BigInteger;

public class ElGamalPrivateKeySpec extends ElGamalKeySpec {
    private BigInteger x;

    public ElGamalPrivateKeySpec(BigInteger x2, ElGamalParameterSpec spec) {
        super(spec);
        this.x = x2;
    }

    public BigInteger getX() {
        return this.x;
    }
}
