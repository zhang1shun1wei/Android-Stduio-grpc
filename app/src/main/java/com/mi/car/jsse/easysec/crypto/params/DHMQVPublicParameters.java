package com.mi.car.jsse.easysec.crypto.params;

import com.mi.car.jsse.easysec.crypto.CipherParameters;

public class DHMQVPublicParameters implements CipherParameters {
    private DHPublicKeyParameters ephemeralPublicKey;
    private DHPublicKeyParameters staticPublicKey;

    public DHMQVPublicParameters(DHPublicKeyParameters staticPublicKey2, DHPublicKeyParameters ephemeralPublicKey2) {
        if (staticPublicKey2 == null) {
            throw new NullPointerException("staticPublicKey cannot be null");
        } else if (ephemeralPublicKey2 == null) {
            throw new NullPointerException("ephemeralPublicKey cannot be null");
        } else if (!staticPublicKey2.getParameters().equals(ephemeralPublicKey2.getParameters())) {
            throw new IllegalArgumentException("Static and ephemeral public keys have different domain parameters");
        } else {
            this.staticPublicKey = staticPublicKey2;
            this.ephemeralPublicKey = ephemeralPublicKey2;
        }
    }

    public DHPublicKeyParameters getStaticPublicKey() {
        return this.staticPublicKey;
    }

    public DHPublicKeyParameters getEphemeralPublicKey() {
        return this.ephemeralPublicKey;
    }
}
