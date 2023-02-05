package com.mi.car.jsse.easysec.crypto.params;

import com.mi.car.jsse.easysec.crypto.CipherParameters;
import com.mi.car.jsse.easysec.crypto.Digest;
import com.mi.car.jsse.easysec.util.Memoable;
import java.math.BigInteger;

public class CramerShoupParameters implements CipherParameters {
    private Digest H;
    private BigInteger g1;
    private BigInteger g2;
    private BigInteger p;

    public CramerShoupParameters(BigInteger p2, BigInteger g12, BigInteger g22, Digest H2) {
        this.p = p2;
        this.g1 = g12;
        this.g2 = g22;
        this.H = (Digest) ((Memoable) H2).copy();
        this.H.reset();
    }

    public boolean equals(Object obj) {
        if (!(obj instanceof CramerShoupParameters)) {
            return false;
        }
        CramerShoupParameters pm = (CramerShoupParameters) obj;
        if (!pm.getP().equals(this.p) || !pm.getG1().equals(this.g1) || !pm.getG2().equals(this.g2)) {
            return false;
        }
        return true;
    }

    public int hashCode() {
        return (getP().hashCode() ^ getG1().hashCode()) ^ getG2().hashCode();
    }

    public BigInteger getG1() {
        return this.g1;
    }

    public BigInteger getG2() {
        return this.g2;
    }

    public BigInteger getP() {
        return this.p;
    }

    public Digest getH() {
        return (Digest) ((Memoable) this.H).copy();
    }
}
