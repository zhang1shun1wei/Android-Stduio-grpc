package com.mi.car.jsse.easysec.pqc.crypto.mceliece;

import com.mi.car.jsse.easysec.pqc.math.linearalgebra.GF2Matrix;

public class McElieceCCA2PublicKeyParameters extends McElieceCCA2KeyParameters {
    private GF2Matrix matrixG;
    private int n;
    private int t;

    public McElieceCCA2PublicKeyParameters(int n2, int t2, GF2Matrix matrix, String digest) {
        super(false, digest);
        this.n = n2;
        this.t = t2;
        this.matrixG = new GF2Matrix(matrix);
    }

    public int getN() {
        return this.n;
    }

    public int getT() {
        return this.t;
    }

    public GF2Matrix getG() {
        return this.matrixG;
    }

    public int getK() {
        return this.matrixG.getNumRows();
    }
}
