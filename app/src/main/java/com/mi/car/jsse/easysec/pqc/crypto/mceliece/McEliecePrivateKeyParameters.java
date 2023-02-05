package com.mi.car.jsse.easysec.pqc.crypto.mceliece;

import com.mi.car.jsse.easysec.pqc.math.linearalgebra.GF2Matrix;
import com.mi.car.jsse.easysec.pqc.math.linearalgebra.GF2mField;
import com.mi.car.jsse.easysec.pqc.math.linearalgebra.GoppaCode;
import com.mi.car.jsse.easysec.pqc.math.linearalgebra.Permutation;
import com.mi.car.jsse.easysec.pqc.math.linearalgebra.PolynomialGF2mSmallM;
import com.mi.car.jsse.easysec.pqc.math.linearalgebra.PolynomialRingGF2m;

public class McEliecePrivateKeyParameters extends McElieceKeyParameters {
    private GF2mField field;
    private PolynomialGF2mSmallM goppaPoly;
    private GF2Matrix h;
    private int k;
    private int n;
    private String oid;
    private Permutation p1;
    private Permutation p2;
    private PolynomialGF2mSmallM[] qInv;
    private GF2Matrix sInv;

    public McEliecePrivateKeyParameters(int n2, int k2, GF2mField field2, PolynomialGF2mSmallM gp, Permutation p12, Permutation p22, GF2Matrix sInv2) {
        super(true, null);
        this.k = k2;
        this.n = n2;
        this.field = field2;
        this.goppaPoly = gp;
        this.sInv = sInv2;
        this.p1 = p12;
        this.p2 = p22;
        this.h = GoppaCode.createCanonicalCheckMatrix(field2, gp);
        this.qInv = new PolynomialRingGF2m(field2, gp).getSquareRootMatrix();
    }

    public McEliecePrivateKeyParameters(int n2, int k2, byte[] encField, byte[] encGoppaPoly, byte[] encSInv, byte[] encP1, byte[] encP2, byte[] encH, byte[][] encQInv) {
        super(true, null);
        this.n = n2;
        this.k = k2;
        this.field = new GF2mField(encField);
        this.goppaPoly = new PolynomialGF2mSmallM(this.field, encGoppaPoly);
        this.sInv = new GF2Matrix(encSInv);
        this.p1 = new Permutation(encP1);
        this.p2 = new Permutation(encP2);
        this.h = new GF2Matrix(encH);
        this.qInv = new PolynomialGF2mSmallM[encQInv.length];
        for (int i = 0; i < encQInv.length; i++) {
            this.qInv[i] = new PolynomialGF2mSmallM(this.field, encQInv[i]);
        }
    }

    public int getN() {
        return this.n;
    }

    public int getK() {
        return this.k;
    }

    public GF2mField getField() {
        return this.field;
    }

    public PolynomialGF2mSmallM getGoppaPoly() {
        return this.goppaPoly;
    }

    public GF2Matrix getSInv() {
        return this.sInv;
    }

    public Permutation getP1() {
        return this.p1;
    }

    public Permutation getP2() {
        return this.p2;
    }

    public GF2Matrix getH() {
        return this.h;
    }

    public PolynomialGF2mSmallM[] getQInv() {
        return this.qInv;
    }
}
