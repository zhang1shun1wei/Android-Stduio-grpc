package com.mi.car.jsse.easysec.crypto.params;

import java.math.BigInteger;

public class GOST3410PublicKeyParameters extends GOST3410KeyParameters {
    private BigInteger y;

    public GOST3410PublicKeyParameters(BigInteger y2, GOST3410Parameters params) {
        super(false, params);
        this.y = y2;
    }

    public BigInteger getY() {
        return this.y;
    }
}
