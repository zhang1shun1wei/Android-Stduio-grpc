package com.mi.car.jsse.easysec.pqc.jcajce.spec;

import com.mi.car.jsse.easysec.pqc.math.linearalgebra.PolynomialRingGF2;
import java.security.InvalidParameterException;
import java.security.spec.AlgorithmParameterSpec;

public class McElieceKeyGenParameterSpec implements AlgorithmParameterSpec {
    public static final int DEFAULT_M = 11;
    public static final int DEFAULT_T = 50;
    private int fieldPoly;
    private int m;
    private int n;
    private int t;

    public McElieceKeyGenParameterSpec() {
        this(11, 50);
    }

    public McElieceKeyGenParameterSpec(int keysize) {
        if (keysize < 1) {
            throw new IllegalArgumentException("key size must be positive");
        }
        this.m = 0;
        this.n = 1;
        while (this.n < keysize) {
            this.n <<= 1;
            this.m++;
        }
        this.t = this.n >>> 1;
        this.t /= this.m;
        this.fieldPoly = PolynomialRingGF2.getIrreduciblePolynomial(this.m);
    }

    public McElieceKeyGenParameterSpec(int m2, int t2) throws InvalidParameterException {
        if (m2 < 1) {
            throw new IllegalArgumentException("m must be positive");
        } else if (m2 > 32) {
            throw new IllegalArgumentException("m is too large");
        } else {
            this.m = m2;
            this.n = 1 << m2;
            if (t2 < 0) {
                throw new IllegalArgumentException("t must be positive");
            } else if (t2 > this.n) {
                throw new IllegalArgumentException("t must be less than n = 2^m");
            } else {
                this.t = t2;
                this.fieldPoly = PolynomialRingGF2.getIrreduciblePolynomial(m2);
            }
        }
    }

    public McElieceKeyGenParameterSpec(int m2, int t2, int poly) {
        this.m = m2;
        if (m2 < 1) {
            throw new IllegalArgumentException("m must be positive");
        } else if (m2 > 32) {
            throw new IllegalArgumentException(" m is too large");
        } else {
            this.n = 1 << m2;
            this.t = t2;
            if (t2 < 0) {
                throw new IllegalArgumentException("t must be positive");
            } else if (t2 > this.n) {
                throw new IllegalArgumentException("t must be less than n = 2^m");
            } else if (PolynomialRingGF2.degree(poly) != m2 || !PolynomialRingGF2.isIrreducible(poly)) {
                throw new IllegalArgumentException("polynomial is not a field polynomial for GF(2^m)");
            } else {
                this.fieldPoly = poly;
            }
        }
    }

    public int getM() {
        return this.m;
    }

    public int getN() {
        return this.n;
    }

    public int getT() {
        return this.t;
    }

    public int getFieldPoly() {
        return this.fieldPoly;
    }
}
