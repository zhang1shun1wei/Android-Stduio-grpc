package com.mi.car.jsse.easysec.jce.spec;

import java.math.BigInteger;

public class ElGamalPublicKeySpec extends ElGamalKeySpec {
    private BigInteger y;

    public ElGamalPublicKeySpec(BigInteger y2, ElGamalParameterSpec spec) {
        super(spec);
        this.y = y2;
    }

    public BigInteger getY() {
        return this.y;
    }
}
