package com.mi.car.jsse.easysec.crypto.params;

import com.mi.car.jsse.easysec.crypto.CipherParameters;
import com.mi.car.jsse.easysec.math.ec.ECMultiplier;
import com.mi.car.jsse.easysec.math.ec.ECPoint;
import com.mi.car.jsse.easysec.math.ec.FixedPointCombMultiplier;

public class SM2KeyExchangePrivateParameters implements CipherParameters {
    private final ECPrivateKeyParameters ephemeralPrivateKey;
    private final ECPoint ephemeralPublicPoint;
    private final boolean initiator;
    private final ECPrivateKeyParameters staticPrivateKey;
    private final ECPoint staticPublicPoint;

    public SM2KeyExchangePrivateParameters(boolean initiator2, ECPrivateKeyParameters staticPrivateKey2, ECPrivateKeyParameters ephemeralPrivateKey2) {
        if (staticPrivateKey2 == null) {
            throw new NullPointerException("staticPrivateKey cannot be null");
        } else if (ephemeralPrivateKey2 == null) {
            throw new NullPointerException("ephemeralPrivateKey cannot be null");
        } else {
            ECDomainParameters parameters = staticPrivateKey2.getParameters();
            if (!parameters.equals(ephemeralPrivateKey2.getParameters())) {
                throw new IllegalArgumentException("Static and ephemeral private keys have different domain parameters");
            }
            ECMultiplier m = new FixedPointCombMultiplier();
            this.initiator = initiator2;
            this.staticPrivateKey = staticPrivateKey2;
            this.staticPublicPoint = m.multiply(parameters.getG(), staticPrivateKey2.getD()).normalize();
            this.ephemeralPrivateKey = ephemeralPrivateKey2;
            this.ephemeralPublicPoint = m.multiply(parameters.getG(), ephemeralPrivateKey2.getD()).normalize();
        }
    }

    public boolean isInitiator() {
        return this.initiator;
    }

    public ECPrivateKeyParameters getStaticPrivateKey() {
        return this.staticPrivateKey;
    }

    public ECPoint getStaticPublicPoint() {
        return this.staticPublicPoint;
    }

    public ECPrivateKeyParameters getEphemeralPrivateKey() {
        return this.ephemeralPrivateKey;
    }

    public ECPoint getEphemeralPublicPoint() {
        return this.ephemeralPublicPoint;
    }
}
