package com.mi.car.jsse.easysec.tls.crypto;

import java.math.BigInteger;

public class TlsSRPConfig {
    protected BigInteger[] explicitNG;

    public BigInteger[] getExplicitNG() {
        return (BigInteger[]) this.explicitNG.clone();
    }

    public void setExplicitNG(BigInteger[] explicitNG2) {
        this.explicitNG = (BigInteger[]) explicitNG2.clone();
    }
}
