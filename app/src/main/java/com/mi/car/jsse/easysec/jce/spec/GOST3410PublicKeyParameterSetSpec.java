package com.mi.car.jsse.easysec.jce.spec;

import java.math.BigInteger;

public class GOST3410PublicKeyParameterSetSpec {
    private BigInteger a;
    private BigInteger p;
    private BigInteger q;

    public GOST3410PublicKeyParameterSetSpec(BigInteger p2, BigInteger q2, BigInteger a2) {
        this.p = p2;
        this.q = q2;
        this.a = a2;
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

    public boolean equals(Object o) {
        if (!(o instanceof GOST3410PublicKeyParameterSetSpec)) {
            return false;
        }
        GOST3410PublicKeyParameterSetSpec other = (GOST3410PublicKeyParameterSetSpec) o;
        if (!this.a.equals(other.a) || !this.p.equals(other.p) || !this.q.equals(other.q)) {
            return false;
        }
        return true;
    }

    public int hashCode() {
        return (this.a.hashCode() ^ this.p.hashCode()) ^ this.q.hashCode();
    }
}
