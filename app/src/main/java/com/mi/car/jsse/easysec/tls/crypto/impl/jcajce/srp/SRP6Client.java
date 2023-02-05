package com.mi.car.jsse.easysec.tls.crypto.impl.jcajce.srp;

import com.mi.car.jsse.easysec.tls.crypto.SRP6Group;
import com.mi.car.jsse.easysec.tls.crypto.TlsHash;
import java.math.BigInteger;
import java.security.SecureRandom;

public class SRP6Client {
    protected BigInteger A;
    protected BigInteger B;
    protected BigInteger Key;
    protected BigInteger M1;
    protected BigInteger M2;
    protected BigInteger N;
    protected BigInteger S;
    protected BigInteger a;
    protected TlsHash digest;
    protected BigInteger g;
    protected SecureRandom random;
    protected BigInteger u;
    protected BigInteger x;

    public void init(BigInteger N2, BigInteger g2, TlsHash digest2, SecureRandom random2) {
        this.N = N2;
        this.g = g2;
        this.digest = digest2;
        this.random = random2;
    }

    public void init(SRP6Group group, TlsHash digest2, SecureRandom random2) {
        init(group.getN(), group.getG(), digest2, random2);
    }

    public BigInteger generateClientCredentials(byte[] salt, byte[] identity, byte[] password) {
        this.x = SRP6Util.calculateX(this.digest, this.N, salt, identity, password);
        this.a = selectPrivateValue();
        this.A = this.g.modPow(this.a, this.N);
        return this.A;
    }

    public BigInteger calculateSecret(BigInteger serverB) {
        this.B = SRP6Util.validatePublicValue(this.N, serverB);
        this.u = SRP6Util.calculateU(this.digest, this.N, this.A, this.B);
        this.S = calculateS();
        return this.S;
    }

    /* access modifiers changed from: protected */
    public BigInteger selectPrivateValue() {
        return SRP6Util.generatePrivateValue(this.N, this.g, this.random);
    }

    private BigInteger calculateS() {
        BigInteger k = SRP6Util.calculateK(this.digest, this.N, this.g);
        return this.B.subtract(this.g.modPow(this.x, this.N).multiply(k).mod(this.N)).mod(this.N).modPow(this.u.multiply(this.x).add(this.a), this.N);
    }

    public BigInteger calculateClientEvidenceMessage() throws IllegalStateException {
        if (this.A == null || this.B == null || this.S == null) {
            throw new IllegalStateException("Impossible to compute M1: some data are missing from the previous operations (A,B,S)");
        }
        this.M1 = SRP6Util.calculateM1(this.digest, this.N, this.A, this.B, this.S);
        return this.M1;
    }

    public boolean verifyServerEvidenceMessage(BigInteger serverM2) throws IllegalStateException {
        if (this.A == null || this.M1 == null || this.S == null) {
            throw new IllegalStateException("Impossible to compute and verify M2: some data are missing from the previous operations (A,M1,S)");
        } else if (!SRP6Util.calculateM2(this.digest, this.N, this.A, this.M1, this.S).equals(serverM2)) {
            return false;
        } else {
            this.M2 = serverM2;
            return true;
        }
    }

    public BigInteger calculateSessionKey() throws IllegalStateException {
        if (this.S == null || this.M1 == null || this.M2 == null) {
            throw new IllegalStateException("Impossible to compute Key: some data are missing from the previous operations (S,M1,M2)");
        }
        this.Key = SRP6Util.calculateKey(this.digest, this.N, this.S);
        return this.Key;
    }
}
