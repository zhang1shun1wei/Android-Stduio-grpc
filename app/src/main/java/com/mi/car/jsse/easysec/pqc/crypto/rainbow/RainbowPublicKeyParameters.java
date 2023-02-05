package com.mi.car.jsse.easysec.pqc.crypto.rainbow;

public class RainbowPublicKeyParameters extends RainbowKeyParameters {
    private short[][] coeffquadratic;
    private short[] coeffscalar;
    private short[][] coeffsingular;

    public RainbowPublicKeyParameters(int docLength, short[][] coeffQuadratic, short[][] coeffSingular, short[] coeffScalar) {
        super(false, docLength);
        this.coeffquadratic = coeffQuadratic;
        this.coeffsingular = coeffSingular;
        this.coeffscalar = coeffScalar;
    }

    public short[][] getCoeffQuadratic() {
        return this.coeffquadratic;
    }

    public short[][] getCoeffSingular() {
        return this.coeffsingular;
    }

    public short[] getCoeffScalar() {
        return this.coeffscalar;
    }
}
