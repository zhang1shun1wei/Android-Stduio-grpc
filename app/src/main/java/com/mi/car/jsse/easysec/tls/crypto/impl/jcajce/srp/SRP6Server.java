package com.mi.car.jsse.easysec.tls.crypto.impl.jcajce.srp;

import com.mi.car.jsse.easysec.tls.crypto.SRP6Group;
import com.mi.car.jsse.easysec.tls.crypto.TlsHash;
import java.math.BigInteger;
import java.security.SecureRandom;

public class SRP6Server {
    protected BigInteger A;
    protected BigInteger B;
    protected BigInteger Key;
    protected BigInteger M1;
    protected BigInteger M2;
    protected BigInteger N;
    protected BigInteger S;
    protected BigInteger b;
    protected TlsHash digest;
    protected BigInteger g;
    protected SecureRandom random;
    protected BigInteger u;
    protected BigInteger v;

    public void init(BigInteger N2, BigInteger g2, BigInteger v2, TlsHash digest2, SecureRandom random2) {
        this.N = N2;
        this.g = g2;
        this.v = v2;
        this.random = random2;
        this.digest = digest2;
    }

    public void init(SRP6Group group, BigInteger v2, TlsHash digest2, SecureRandom random2) {
        init(group.getN(), group.getG(), v2, digest2, random2);
    }

    public BigInteger generateServerCredentials() {
        BigInteger k = SRP6Util.calculateK(this.digest, this.N, this.g);
        this.b = selectPrivateValue();
        this.B = k.multiply(this.v).mod(this.N).add(this.g.modPow(this.b, this.N)).mod(this.N);
        return this.B;
    }

    public BigInteger calculateSecret(BigInteger clientA) throws IllegalArgumentException {
        this.A = SRP6Util.validatePublicValue(this.N, clientA);
        this.u = SRP6Util.calculateU(this.digest, this.N, this.A, this.B);
        this.S = calculateS();
        return this.S;
    }

    /* access modifiers changed from: protected */
    public BigInteger selectPrivateValue() {
        return SRP6Util.generatePrivateValue(this.N, this.g, this.random);
    }

    private BigInteger calculateS() {
        return this.v.modPow(this.u, this.N).multiply(this.A).mod(this.N).modPow(this.b, this.N);
    }

    public boolean verifyClientEvidenceMessage(BigInteger clientM1) throws IllegalStateException {
        if (this.A == null || this.B == null || this.S == null) {
            throw new IllegalStateException("Impossible to compute and verify M1: some data are missing from the previous operations (A,B,S)");
        } else if (!SRP6Util.calculateM1(this.digest, this.N, this.A, this.B, this.S).equals(clientM1)) {
            return false;
        } else {
            this.M1 = clientM1;
            return true;
        }
    }

    public BigInteger calculateServerEvidenceMessage() throws IllegalStateException {
        if (this.A == null || this.M1 == null || this.S == null) {
            throw new IllegalStateException("Impossible to compute M2: some data are missing from the previous operations (A,M1,S)");
        }
        this.M2 = SRP6Util.calculateM2(this.digest, this.N, this.A, this.M1, this.S);
        return this.M2;
    }

    public BigInteger calculateSessionKey() throws IllegalArgumentException {
        if (this.S == null || this.M1 == null || this.M2 == null) {
            throw new IllegalStateException("Impossible to compute Key: some data are missing from the previous operations (S,M1,M2)");
        }
        this.Key = SRP6Util.calculateKey(this.digest, this.N, this.S);
        return this.Key;
    }
}
