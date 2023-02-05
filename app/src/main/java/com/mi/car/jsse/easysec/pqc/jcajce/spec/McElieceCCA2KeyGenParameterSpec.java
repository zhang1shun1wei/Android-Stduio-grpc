package com.mi.car.jsse.easysec.pqc.jcajce.spec;

import com.mi.car.jsse.easysec.pqc.math.linearalgebra.PolynomialRingGF2;
import java.security.spec.AlgorithmParameterSpec;

public class McElieceCCA2KeyGenParameterSpec implements AlgorithmParameterSpec {
    public static final int DEFAULT_M = 11;
    public static final int DEFAULT_T = 50;
    public static final String SHA1 = "SHA-1";
    public static final String SHA224 = "SHA-224";
    public static final String SHA256 = "SHA-256";
    public static final String SHA384 = "SHA-384";
    public static final String SHA512 = "SHA-512";
    private final String digest;
    private int fieldPoly;
    private final int m;
    private final int n;
    private final int t;

    public McElieceCCA2KeyGenParameterSpec() {
        this(11, 50, "SHA-256");
    }

    public McElieceCCA2KeyGenParameterSpec(int keysize) {
        this(keysize, "SHA-256");
    }

    public McElieceCCA2KeyGenParameterSpec(int keysize, String digest2) {
        if (keysize < 1) {
            throw new IllegalArgumentException("key size must be positive");
        }
        int m2 = 0;
        int n2 = 1;
        while (n2 < keysize) {
            n2 <<= 1;
            m2++;
        }
        this.t = (n2 >>> 1) / m2;
        this.m = m2;
        this.n = n2;
        this.fieldPoly = PolynomialRingGF2.getIrreduciblePolynomial(m2);
        this.digest = digest2;
    }

    public McElieceCCA2KeyGenParameterSpec(int m2, int t2) {
        this(m2, t2, "SHA-256");
    }

    public McElieceCCA2KeyGenParameterSpec(int m2, int t2, String digest2) {
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
                this.digest = digest2;
            }
        }
    }

    public McElieceCCA2KeyGenParameterSpec(int m2, int t2, int poly) {
        this(m2, t2, poly, "SHA-256");
    }

    public McElieceCCA2KeyGenParameterSpec(int m2, int t2, int poly, String digest2) {
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
                this.digest = digest2;
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

    public String getDigest() {
        return this.digest;
    }
}
