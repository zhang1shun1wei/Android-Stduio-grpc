package com.mi.car.jsse.easysec.crypto.params;

import com.mi.car.jsse.easysec.math.ec.ECPoint;

public class ECPublicKeyParameters extends ECKeyParameters {
    private final ECPoint q;

    public ECPublicKeyParameters(ECPoint q2, ECDomainParameters parameters) {
        super(false, parameters);
        this.q = parameters.validatePublicPoint(q2);
    }

    public ECPoint getQ() {
        return this.q;
    }
}
