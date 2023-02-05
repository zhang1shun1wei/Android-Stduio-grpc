package com.mi.car.jsse.easysec.pqc.jcajce.spec;

import java.security.spec.KeySpec;

public class RainbowPublicKeySpec implements KeySpec {
    private short[][] coeffquadratic;
    private short[] coeffscalar;
    private short[][] coeffsingular;
    private int docLength;

    public RainbowPublicKeySpec(int docLength2, short[][] coeffquadratic2, short[][] coeffSingular, short[] coeffScalar) {
        this.docLength = docLength2;
        this.coeffquadratic = coeffquadratic2;
        this.coeffsingular = coeffSingular;
        this.coeffscalar = coeffScalar;
    }

    public int getDocLength() {
        return this.docLength;
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
