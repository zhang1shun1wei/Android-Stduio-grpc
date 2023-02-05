package com.mi.car.jsse.easysec.pqc.crypto.mceliece;

import com.mi.car.jsse.easysec.pqc.math.linearalgebra.GF2Matrix;

public class McEliecePublicKeyParameters extends McElieceKeyParameters {
    private GF2Matrix g;
    private int n;
    private int t;

    public McEliecePublicKeyParameters(int n2, int t2, GF2Matrix g2) {
        super(false, null);
        this.n = n2;
        this.t = t2;
        this.g = new GF2Matrix(g2);
    }

    public int getN() {
        return this.n;
    }

    public int getT() {
        return this.t;
    }

    public GF2Matrix getG() {
        return this.g;
    }

    public int getK() {
        return this.g.getNumRows();
    }
}
