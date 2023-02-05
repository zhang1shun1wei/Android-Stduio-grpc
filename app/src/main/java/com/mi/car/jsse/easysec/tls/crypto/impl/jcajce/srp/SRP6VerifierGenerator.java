package com.mi.car.jsse.easysec.tls.crypto.impl.jcajce.srp;

import com.mi.car.jsse.easysec.tls.crypto.SRP6Group;
import com.mi.car.jsse.easysec.tls.crypto.TlsHash;
import java.math.BigInteger;

public class SRP6VerifierGenerator {
    protected BigInteger N;
    protected TlsHash digest;
    protected BigInteger g;

    public void init(BigInteger N2, BigInteger g2, TlsHash digest2) {
        this.N = N2;
        this.g = g2;
        this.digest = digest2;
    }

    public void init(SRP6Group group, TlsHash digest2) {
        this.N = group.getN();
        this.g = group.getG();
        this.digest = digest2;
    }

    public BigInteger generateVerifier(byte[] salt, byte[] identity, byte[] password) {
        return this.g.modPow(SRP6Util.calculateX(this.digest, this.N, salt, identity, password), this.N);
    }
}
