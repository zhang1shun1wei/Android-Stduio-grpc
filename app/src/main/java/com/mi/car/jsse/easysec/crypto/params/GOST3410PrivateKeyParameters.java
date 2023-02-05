package com.mi.car.jsse.easysec.crypto.params;

import java.math.BigInteger;

public class GOST3410PrivateKeyParameters extends GOST3410KeyParameters {
    private BigInteger x;

    public GOST3410PrivateKeyParameters(BigInteger x2, GOST3410Parameters params) {
        super(true, params);
        this.x = x2;
    }

    public BigInteger getX() {
        return this.x;
    }
}
