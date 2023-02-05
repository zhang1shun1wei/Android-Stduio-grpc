package com.mi.car.jsse.easysec.crypto.params;

import com.mi.car.jsse.easysec.crypto.CipherParameters;
import java.math.BigInteger;

public class RSABlindingParameters implements CipherParameters {
    private BigInteger blindingFactor;
    private RSAKeyParameters publicKey;

    public RSABlindingParameters(RSAKeyParameters publicKey2, BigInteger blindingFactor2) {
        if (publicKey2 instanceof RSAPrivateCrtKeyParameters) {
            throw new IllegalArgumentException("RSA parameters should be for a public key");
        }
        this.publicKey = publicKey2;
        this.blindingFactor = blindingFactor2;
    }

    public RSAKeyParameters getPublicKey() {
        return this.publicKey;
    }

    public BigInteger getBlindingFactor() {
        return this.blindingFactor;
    }
}
