package com.mi.car.jsse.easysec.crypto.params;

import com.mi.car.jsse.easysec.crypto.CipherParameters;

public class MQVPublicParameters implements CipherParameters {
    private ECPublicKeyParameters ephemeralPublicKey;
    private ECPublicKeyParameters staticPublicKey;

    public MQVPublicParameters(ECPublicKeyParameters staticPublicKey2, ECPublicKeyParameters ephemeralPublicKey2) {
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

    public ECPublicKeyParameters getStaticPublicKey() {
        return this.staticPublicKey;
    }

    public ECPublicKeyParameters getEphemeralPublicKey() {
        return this.ephemeralPublicKey;
    }
}
