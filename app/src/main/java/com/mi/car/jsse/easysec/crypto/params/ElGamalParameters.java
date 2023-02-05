package com.mi.car.jsse.easysec.crypto.params;

import com.mi.car.jsse.easysec.crypto.CipherParameters;
import java.math.BigInteger;

public class ElGamalParameters implements CipherParameters {
    private BigInteger g;
    private int l;
    private BigInteger p;

    public ElGamalParameters(BigInteger p2, BigInteger g2) {
        this(p2, g2, 0);
    }

    public ElGamalParameters(BigInteger p2, BigInteger g2, int l2) {
        this.g = g2;
        this.p = p2;
        this.l = l2;
    }

    public BigInteger getP() {
        return this.p;
    }

    public BigInteger getG() {
        return this.g;
    }

    public int getL() {
        return this.l;
    }

    public boolean equals(Object obj) {
        if (!(obj instanceof ElGamalParameters)) {
            return false;
        }
        ElGamalParameters pm = (ElGamalParameters) obj;
        if (!pm.getP().equals(this.p) || !pm.getG().equals(this.g) || pm.getL() != this.l) {
            return false;
        }
        return true;
    }

    public int hashCode() {
        return (getP().hashCode() ^ getG().hashCode()) + this.l;
    }
}
