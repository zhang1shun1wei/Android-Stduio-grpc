package com.mi.car.jsse.easysec.crypto.params;

import com.mi.car.jsse.easysec.crypto.CipherParameters;

public class XDHUPublicParameters implements CipherParameters {
    private AsymmetricKeyParameter ephemeralPublicKey;
    private AsymmetricKeyParameter staticPublicKey;

    public XDHUPublicParameters(AsymmetricKeyParameter staticPublicKey2, AsymmetricKeyParameter ephemeralPublicKey2) {
        if (staticPublicKey2 == null) {
            throw new NullPointerException("staticPublicKey cannot be null");
        } else if (!(staticPublicKey2 instanceof X448PublicKeyParameters) && !(staticPublicKey2 instanceof X25519PublicKeyParameters)) {
            throw new IllegalArgumentException("only X25519 and X448 paramaters can be used");
        } else if (ephemeralPublicKey2 == null) {
            throw new NullPointerException("ephemeralPublicKey cannot be null");
        } else if (!staticPublicKey2.getClass().isAssignableFrom(ephemeralPublicKey2.getClass())) {
            throw new IllegalArgumentException("static and ephemeral public keys have different domain parameters");
        } else {
            this.staticPublicKey = staticPublicKey2;
            this.ephemeralPublicKey = ephemeralPublicKey2;
        }
    }

    public AsymmetricKeyParameter getStaticPublicKey() {
        return this.staticPublicKey;
    }

    public AsymmetricKeyParameter getEphemeralPublicKey() {
        return this.ephemeralPublicKey;
    }
}
