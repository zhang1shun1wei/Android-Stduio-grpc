package com.mi.car.jsse.easysec.jce.spec;

import java.math.BigInteger;
import java.security.spec.KeySpec;

public class GOST3410PrivateKeySpec implements KeySpec {
    private BigInteger a;
    private BigInteger p;
    private BigInteger q;
    private BigInteger x;

    public GOST3410PrivateKeySpec(BigInteger x2, BigInteger p2, BigInteger q2, BigInteger a2) {
        this.x = x2;
        this.p = p2;
        this.q = q2;
        this.a = a2;
    }

    public BigInteger getX() {
        return this.x;
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
