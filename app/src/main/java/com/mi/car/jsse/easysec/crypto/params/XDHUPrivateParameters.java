package com.mi.car.jsse.easysec.crypto.params;

import com.mi.car.jsse.easysec.crypto.CipherParameters;

public class XDHUPrivateParameters implements CipherParameters {
    private AsymmetricKeyParameter ephemeralPrivateKey;
    private AsymmetricKeyParameter ephemeralPublicKey;
    private AsymmetricKeyParameter staticPrivateKey;

    public XDHUPrivateParameters(AsymmetricKeyParameter staticPrivateKey2, AsymmetricKeyParameter ephemeralPrivateKey2) {
        this(staticPrivateKey2, ephemeralPrivateKey2, null);
    }

    public XDHUPrivateParameters(AsymmetricKeyParameter staticPrivateKey2, AsymmetricKeyParameter ephemeralPrivateKey2, AsymmetricKeyParameter ephemeralPublicKey2) {
        if (staticPrivateKey2 == null) {
            throw new NullPointerException("staticPrivateKey cannot be null");
        } else if (!(staticPrivateKey2 instanceof X448PrivateKeyParameters) && !(staticPrivateKey2 instanceof X25519PrivateKeyParameters)) {
            throw new IllegalArgumentException("only X25519 and X448 paramaters can be used");
        } else if (ephemeralPrivateKey2 == null) {
            throw new NullPointerException("ephemeralPrivateKey cannot be null");
        } else if (!staticPrivateKey2.getClass().isAssignableFrom(ephemeralPrivateKey2.getClass())) {
            throw new IllegalArgumentException("static and ephemeral private keys have different domain parameters");
        } else {
            if (ephemeralPublicKey2 == null) {
                if (ephemeralPrivateKey2 instanceof X448PrivateKeyParameters) {
                    ephemeralPublicKey2 = ((X448PrivateKeyParameters) ephemeralPrivateKey2).generatePublicKey();
                } else {
                    ephemeralPublicKey2 = ((X25519PrivateKeyParameters) ephemeralPrivateKey2).generatePublicKey();
                }
            } else if ((ephemeralPublicKey2 instanceof X448PublicKeyParameters) && !(staticPrivateKey2 instanceof X448PrivateKeyParameters)) {
                throw new IllegalArgumentException("ephemeral public key has different domain parameters");
            } else if ((ephemeralPublicKey2 instanceof X25519PublicKeyParameters) && !(staticPrivateKey2 instanceof X25519PrivateKeyParameters)) {
                throw new IllegalArgumentException("ephemeral public key has different domain parameters");
            }
            this.staticPrivateKey = staticPrivateKey2;
            this.ephemeralPrivateKey = ephemeralPrivateKey2;
            this.ephemeralPublicKey = ephemeralPublicKey2;
        }
    }

    public AsymmetricKeyParameter getStaticPrivateKey() {
        return this.staticPrivateKey;
    }

    public AsymmetricKeyParameter getEphemeralPrivateKey() {
        return this.ephemeralPrivateKey;
    }

    public AsymmetricKeyParameter getEphemeralPublicKey() {
        return this.ephemeralPublicKey;
    }
}
