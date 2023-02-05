package com.mi.car.jsse.easysec.crypto.params;

import java.math.BigInteger;

public class ECPrivateKeyParameters extends ECKeyParameters {
    private final BigInteger d;

    public ECPrivateKeyParameters(BigInteger d2, ECDomainParameters parameters) {
        super(true, parameters);
        this.d = parameters.validatePrivateScalar(d2);
    }

    public BigInteger getD() {
        return this.d;
    }
}
