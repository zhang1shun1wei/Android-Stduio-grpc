package com.mi.car.jsse.easysec.crypto.params;

import java.math.BigInteger;

public class ElGamalPrivateKeyParameters extends ElGamalKeyParameters {
    private BigInteger x;

    public ElGamalPrivateKeyParameters(BigInteger x2, ElGamalParameters params) {
        super(true, params);
        this.x = x2;
    }

    public BigInteger getX() {
        return this.x;
    }

    @Override // com.mi.car.jsse.easysec.crypto.params.ElGamalKeyParameters
    public boolean equals(Object obj) {
        if ((obj instanceof ElGamalPrivateKeyParameters) && ((ElGamalPrivateKeyParameters) obj).getX().equals(this.x)) {
            return super.equals(obj);
        }
        return false;
    }

    @Override // com.mi.car.jsse.easysec.crypto.params.ElGamalKeyParameters
    public int hashCode() {
        return getX().hashCode();
    }
}
