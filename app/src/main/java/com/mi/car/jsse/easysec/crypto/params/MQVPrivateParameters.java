package com.mi.car.jsse.easysec.crypto.params;

import com.mi.car.jsse.easysec.crypto.CipherParameters;
import com.mi.car.jsse.easysec.math.ec.FixedPointCombMultiplier;

public class MQVPrivateParameters implements CipherParameters {
    private ECPrivateKeyParameters ephemeralPrivateKey;
    private ECPublicKeyParameters ephemeralPublicKey;
    private ECPrivateKeyParameters staticPrivateKey;

    public MQVPrivateParameters(ECPrivateKeyParameters staticPrivateKey2, ECPrivateKeyParameters ephemeralPrivateKey2) {
        this(staticPrivateKey2, ephemeralPrivateKey2, null);
    }

    public MQVPrivateParameters(ECPrivateKeyParameters staticPrivateKey2, ECPrivateKeyParameters ephemeralPrivateKey2, ECPublicKeyParameters ephemeralPublicKey2) {
        if (staticPrivateKey2 == null) {
            throw new NullPointerException("staticPrivateKey cannot be null");
        } else if (ephemeralPrivateKey2 == null) {
            throw new NullPointerException("ephemeralPrivateKey cannot be null");
        } else {
            ECDomainParameters parameters = staticPrivateKey2.getParameters();
            if (!parameters.equals(ephemeralPrivateKey2.getParameters())) {
                throw new IllegalArgumentException("Static and ephemeral private keys have different domain parameters");
            }
            if (ephemeralPublicKey2 == null) {
                ephemeralPublicKey2 = new ECPublicKeyParameters(new FixedPointCombMultiplier().multiply(parameters.getG(), ephemeralPrivateKey2.getD()), parameters);
            } else if (!parameters.equals(ephemeralPublicKey2.getParameters())) {
                throw new IllegalArgumentException("Ephemeral public key has different domain parameters");
            }
            this.staticPrivateKey = staticPrivateKey2;
            this.ephemeralPrivateKey = ephemeralPrivateKey2;
            this.ephemeralPublicKey = ephemeralPublicKey2;
        }
    }

    public ECPrivateKeyParameters getStaticPrivateKey() {
        return this.staticPrivateKey;
    }

    public ECPrivateKeyParameters getEphemeralPrivateKey() {
        return this.ephemeralPrivateKey;
    }

    public ECPublicKeyParameters getEphemeralPublicKey() {
        return this.ephemeralPublicKey;
    }
}
