package com.mi.car.jsse.easysec.jce.spec;

import java.math.BigInteger;
import java.security.spec.KeySpec;

public class GOST3410PublicKeySpec implements KeySpec {
    private BigInteger a;
    private BigInteger p;
    private BigInteger q;
    private BigInteger y;

    public GOST3410PublicKeySpec(BigInteger y2, BigInteger p2, BigInteger q2, BigInteger a2) {
        this.y = y2;
        this.p = p2;
        this.q = q2;
        this.a = a2;
    }

    public BigInteger getY() {
        return this.y;
    }

    public BigInteger getP() {
        return this.p;
    }

    public BigInteger getQ() {
        return this.q;
    }

    public BigInteger getA() {
        return this.a;
    }
}
