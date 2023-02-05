package com.mi.car.jsse.easysec.pqc.crypto.mceliece;

import com.mi.car.jsse.easysec.pqc.math.linearalgebra.GF2Matrix;
import com.mi.car.jsse.easysec.pqc.math.linearalgebra.GF2mField;
import com.mi.car.jsse.easysec.pqc.math.linearalgebra.GoppaCode;
import com.mi.car.jsse.easysec.pqc.math.linearalgebra.Permutation;
import com.mi.car.jsse.easysec.pqc.math.linearalgebra.PolynomialGF2mSmallM;
import com.mi.car.jsse.easysec.pqc.math.linearalgebra.PolynomialRingGF2m;

public class McElieceCCA2PrivateKeyParameters extends McElieceCCA2KeyParameters {
    private GF2mField field;
    private PolynomialGF2mSmallM goppaPoly;
    private GF2Matrix h;
    private int k;
    private int n;
    private Permutation p;
    private PolynomialGF2mSmallM[] qInv;

    public McElieceCCA2PrivateKeyParameters(int n2, int k2, GF2mField field2, PolynomialGF2mSmallM gp, Permutation p2, String digest) {
        this(n2, k2, field2, gp, GoppaCode.createCanonicalCheckMatrix(field2, gp), p2, digest);
    }

    public McElieceCCA2PrivateKeyParameters(int n2, int k2, GF2mField field2, PolynomialGF2mSmallM gp, GF2Matrix canonicalCheckMatrix, Permutation p2, String digest) {
        super(true, digest);
        this.n = n2;
        this.k = k2;
        this.field = field2;
        this.goppaPoly = gp;
        this.h = canonicalCheckMatrix;
        this.p = p2;
        this.qInv = new PolynomialRingGF2m(field2, gp).getSquareRootMatrix();
    }

    public int getN() {
        return this.n;
    }

    public int getK() {
        return this.k;
    }

    public int getT() {
        return this.goppaPoly.getDegree();
    }

    public GF2mField getField() {
        return this.field;
    }

    public PolynomialGF2mSmallM getGoppaPoly() {
        return this.goppaPoly;
    }

    public Permutation getP() {
        return this.p;
    }

    public GF2Matrix getH() {
        return this.h;
    }

    public PolynomialGF2mSmallM[] getQInv() {
        return this.qInv;
    }
}
