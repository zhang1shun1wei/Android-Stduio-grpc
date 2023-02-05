package com.mi.car.jsse.easysec.crypto.params;

import com.mi.car.jsse.easysec.crypto.CipherParameters;
import java.math.BigInteger;

public class GOST3410Parameters implements CipherParameters {
    private BigInteger a;
    private BigInteger p;
    private BigInteger q;
    private GOST3410ValidationParameters validation;

    public GOST3410Parameters(BigInteger p2, BigInteger q2, BigInteger a2) {
        this.p = p2;
        this.q = q2;
        this.a = a2;
    }

    public GOST3410Parameters(BigInteger p2, BigInteger q2, BigInteger a2, GOST3410ValidationParameters params) {
        this.a = a2;
        this.p = p2;
        this.q = q2;
        this.validation = params;
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

    public GOST3410ValidationParameters getValidationParameters() {
        return this.validation;
    }

    public int hashCode() {
        return (this.p.hashCode() ^ this.q.hashCode()) ^ this.a.hashCode();
    }

    public boolean equals(Object obj) {
        if (!(obj instanceof GOST3410Parameters)) {
            return false;
        }
        GOST3410Parameters pm = (GOST3410Parameters) obj;
        if (!pm.getP().equals(this.p) || !pm.getQ().equals(this.q) || !pm.getA().equals(this.a)) {
            return false;
        }
        return true;
    }
}
