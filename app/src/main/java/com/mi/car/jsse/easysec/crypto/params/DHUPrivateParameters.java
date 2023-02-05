package com.mi.car.jsse.easysec.crypto.params;

import com.mi.car.jsse.easysec.crypto.CipherParameters;

public class DHUPrivateParameters implements CipherParameters {
    private DHPrivateKeyParameters ephemeralPrivateKey;
    private DHPublicKeyParameters ephemeralPublicKey;
    private DHPrivateKeyParameters staticPrivateKey;

    public DHUPrivateParameters(DHPrivateKeyParameters staticPrivateKey2, DHPrivateKeyParameters ephemeralPrivateKey2) {
        this(staticPrivateKey2, ephemeralPrivateKey2, null);
    }

    public DHUPrivateParameters(DHPrivateKeyParameters staticPrivateKey2, DHPrivateKeyParameters ephemeralPrivateKey2, DHPublicKeyParameters ephemeralPublicKey2) {
        if (staticPrivateKey2 == null) {
            throw new NullPointerException("staticPrivateKey cannot be null");
        } else if (ephemeralPrivateKey2 == null) {
            throw new NullPointerException("ephemeralPrivateKey cannot be null");
        } else {
            DHParameters parameters = staticPrivateKey2.getParameters();
            if (!parameters.equals(ephemeralPrivateKey2.getParameters())) {
                throw new IllegalArgumentException("static and ephemeral private keys have different domain parameters");
            }
            if (ephemeralPublicKey2 == null) {
                ephemeralPublicKey2 = new DHPublicKeyParameters(parameters.getG().modPow(ephemeralPrivateKey2.getX(), parameters.getP()), parameters);
            } else if (!parameters.equals(ephemeralPublicKey2.getParameters())) {
                throw new IllegalArgumentException("ephemeral public key has different domain parameters");
            }
            this.staticPrivateKey = staticPrivateKey2;
            this.ephemeralPrivateKey = ephemeralPrivateKey2;
            this.ephemeralPublicKey = ephemeralPublicKey2;
        }
    }

    public DHPrivateKeyParameters getStaticPrivateKey() {
        return this.staticPrivateKey;
    }

    public DHPrivateKeyParameters getEphemeralPrivateKey() {
        return this.ephemeralPrivateKey;
    }

    public DHPublicKeyParameters getEphemeralPublicKey() {
        return this.ephemeralPublicKey;
    }
}
