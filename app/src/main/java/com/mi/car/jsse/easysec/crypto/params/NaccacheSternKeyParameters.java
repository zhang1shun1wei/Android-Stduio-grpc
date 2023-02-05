package com.mi.car.jsse.easysec.crypto.params;

import java.math.BigInteger;

public class NaccacheSternKeyParameters extends AsymmetricKeyParameter {
    private BigInteger g;
    int lowerSigmaBound;
    private BigInteger n;

    public NaccacheSternKeyParameters(boolean privateKey, BigInteger g2, BigInteger n2, int lowerSigmaBound2) {
        super(privateKey);
        this.g = g2;
        this.n = n2;
        this.lowerSigmaBound = lowerSigmaBound2;
    }

    public BigInteger getG() {
        return this.g;
    }

    public int getLowerSigmaBound() {
        return this.lowerSigmaBound;
    }

    public BigInteger getModulus() {
        return this.n;
    }
}
