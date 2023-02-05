package com.mi.car.jsse.easysec.crypto.params;

import java.math.BigInteger;

public class CramerShoupPublicKeyParameters extends CramerShoupKeyParameters {
    private BigInteger c;
    private BigInteger d;
    private BigInteger h;

    public CramerShoupPublicKeyParameters(CramerShoupParameters params, BigInteger c2, BigInteger d2, BigInteger h2) {
        super(false, params);
        this.c = c2;
        this.d = d2;
        this.h = h2;
    }

    public BigInteger getC() {
        return this.c;
    }

    public BigInteger getD() {
        return this.d;
    }

    public BigInteger getH() {
        return this.h;
    }

    @Override // com.mi.car.jsse.easysec.crypto.params.CramerShoupKeyParameters
    public int hashCode() {
        return ((this.c.hashCode() ^ this.d.hashCode()) ^ this.h.hashCode()) ^ super.hashCode();
    }

    @Override // com.mi.car.jsse.easysec.crypto.params.CramerShoupKeyParameters
    public boolean equals(Object obj) {
        if (!(obj instanceof CramerShoupPublicKeyParameters)) {
            return false;
        }
        CramerShoupPublicKeyParameters other = (CramerShoupPublicKeyParameters) obj;
        if (!other.getC().equals(this.c) || !other.getD().equals(this.d) || !other.getH().equals(this.h) || !super.equals(obj)) {
            return false;
        }
        return true;
    }
}
