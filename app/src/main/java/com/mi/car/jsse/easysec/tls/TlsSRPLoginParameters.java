package com.mi.car.jsse.easysec.tls;

import com.mi.car.jsse.easysec.tls.crypto.TlsSRPConfig;
import com.mi.car.jsse.easysec.util.Arrays;
import java.math.BigInteger;

public class TlsSRPLoginParameters {
    protected byte[] identity;
    protected byte[] salt;
    protected TlsSRPConfig srpConfig;
    protected BigInteger verifier;

    public TlsSRPLoginParameters(byte[] identity2, TlsSRPConfig srpConfig2, BigInteger verifier2, byte[] salt2) {
        this.identity = Arrays.clone(identity2);
        this.srpConfig = srpConfig2;
        this.verifier = verifier2;
        this.salt = Arrays.clone(salt2);
    }

    public TlsSRPConfig getConfig() {
        return this.srpConfig;
    }

    public byte[] getIdentity() {
        return this.identity;
    }

    public byte[] getSalt() {
        return this.salt;
    }

    public BigInteger getVerifier() {
        return this.verifier;
    }
}
