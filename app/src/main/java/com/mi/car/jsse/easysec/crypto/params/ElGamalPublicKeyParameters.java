package com.mi.car.jsse.easysec.crypto.params;

import java.math.BigInteger;

public class ElGamalPublicKeyParameters extends ElGamalKeyParameters {
    private BigInteger y;

    public ElGamalPublicKeyParameters(BigInteger y2, ElGamalParameters params) {
        super(false, params);
        this.y = y2;
    }

    public BigInteger getY() {
        return this.y;
    }

    @Override // com.mi.car.jsse.easysec.crypto.params.ElGamalKeyParameters
    public int hashCode() {
        return this.y.hashCode() ^ super.hashCode();
    }

    @Override // com.mi.car.jsse.easysec.crypto.params.ElGamalKeyParameters
    public boolean equals(Object obj) {
        if ((obj instanceof ElGamalPublicKeyParameters) && ((ElGamalPublicKeyParameters) obj).getY().equals(this.y) && super.equals(obj)) {
            return true;
        }
        return false;
    }
}
