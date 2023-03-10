package com.mi.car.jsse.easysec.crypto.params;

import java.math.BigInteger;

public class RSAPrivateCrtKeyParameters extends RSAKeyParameters {
    private BigInteger dP;
    private BigInteger dQ;
    private BigInteger e;
    private BigInteger p;
    private BigInteger q;
    private BigInteger qInv;

    public RSAPrivateCrtKeyParameters(BigInteger modulus, BigInteger publicExponent, BigInteger privateExponent, BigInteger p2, BigInteger q2, BigInteger dP2, BigInteger dQ2, BigInteger qInv2) {
        this(modulus, publicExponent, privateExponent, p2, q2, dP2, dQ2, qInv2, false);
    }

    public RSAPrivateCrtKeyParameters(BigInteger modulus, BigInteger publicExponent, BigInteger privateExponent, BigInteger p2, BigInteger q2, BigInteger dP2, BigInteger dQ2, BigInteger qInv2, boolean isInternal) {
        super(true, modulus, privateExponent, isInternal);
        this.e = publicExponent;
        this.p = p2;
        this.q = q2;
        this.dP = dP2;
        this.dQ = dQ2;
        this.qInv = qInv2;
    }

    public BigInteger getPublicExponent() {
        return this.e;
    }

    public BigInteger getP() {
        return this.p;
    }

    public BigInteger getQ() {
        return this.q;
    }

    public BigInteger getDP() {
        return this.dP;
    }

    public BigInteger getDQ() {
        return this.dQ;
    }

    public BigInteger getQInv() {
        return this.qInv;
    }
}
