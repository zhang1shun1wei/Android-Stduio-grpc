package com.mi.car.jsse.easysec.crypto.params;

import java.math.BigInteger;

public class CramerShoupPrivateKeyParameters extends CramerShoupKeyParameters {
    private CramerShoupPublicKeyParameters pk;
    private BigInteger x1;
    private BigInteger x2;
    private BigInteger y1;
    private BigInteger y2;
    private BigInteger z;

    public CramerShoupPrivateKeyParameters(CramerShoupParameters params, BigInteger x12, BigInteger x22, BigInteger y12, BigInteger y22, BigInteger z2) {
        super(true, params);
        this.x1 = x12;
        this.x2 = x22;
        this.y1 = y12;
        this.y2 = y22;
        this.z = z2;
    }

    public BigInteger getX1() {
        return this.x1;
    }

    public BigInteger getX2() {
        return this.x2;
    }

    public BigInteger getY1() {
        return this.y1;
    }

    public BigInteger getY2() {
        return this.y2;
    }

    public BigInteger getZ() {
        return this.z;
    }

    public void setPk(CramerShoupPublicKeyParameters pk2) {
        this.pk = pk2;
    }

    public CramerShoupPublicKeyParameters getPk() {
        return this.pk;
    }

    @Override // com.mi.car.jsse.easysec.crypto.params.CramerShoupKeyParameters
    public int hashCode() {
        return ((((this.x1.hashCode() ^ this.x2.hashCode()) ^ this.y1.hashCode()) ^ this.y2.hashCode()) ^ this.z.hashCode()) ^ super.hashCode();
    }

    @Override // com.mi.car.jsse.easysec.crypto.params.CramerShoupKeyParameters
    public boolean equals(Object obj) {
        if (!(obj instanceof CramerShoupPrivateKeyParameters)) {
            return false;
        }
        CramerShoupPrivateKeyParameters other = (CramerShoupPrivateKeyParameters) obj;
        if (!other.getX1().equals(this.x1) || !other.getX2().equals(this.x2) || !other.getY1().equals(this.y1) || !other.getY2().equals(this.y2) || !other.getZ().equals(this.z) || !super.equals(obj)) {
            return false;
        }
        return true;
    }
}
