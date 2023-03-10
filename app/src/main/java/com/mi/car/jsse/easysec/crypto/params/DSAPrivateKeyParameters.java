package com.mi.car.jsse.easysec.crypto.params;

import java.math.BigInteger;

public class DSAPrivateKeyParameters extends DSAKeyParameters {
    private BigInteger x;

    public DSAPrivateKeyParameters(BigInteger x2, DSAParameters params) {
        super(true, params);
        this.x = x2;
    }

    public BigInteger getX() {
        return this.x;
    }
}
