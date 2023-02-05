package com.mi.car.jsse.easysec.pqc.jcajce.provider.rainbow;

import com.mi.car.jsse.easysec.crypto.params.AsymmetricKeyParameter;
import com.mi.car.jsse.easysec.pqc.crypto.rainbow.RainbowPrivateKeyParameters;
import com.mi.car.jsse.easysec.pqc.crypto.rainbow.RainbowPublicKeyParameters;
import java.security.InvalidKeyException;
import java.security.PrivateKey;
import java.security.PublicKey;

public class RainbowKeysToParams {
    public static AsymmetricKeyParameter generatePublicKeyParameter(PublicKey key) throws InvalidKeyException {
        if (key instanceof BCRainbowPublicKey) {
            BCRainbowPublicKey k = (BCRainbowPublicKey) key;
            return new RainbowPublicKeyParameters(k.getDocLength(), k.getCoeffQuadratic(), k.getCoeffSingular(), k.getCoeffScalar());
        }
        throw new InvalidKeyException("can't identify Rainbow public key: " + key.getClass().getName());
    }

    public static AsymmetricKeyParameter generatePrivateKeyParameter(PrivateKey key) throws InvalidKeyException {
        if (key instanceof BCRainbowPrivateKey) {
            BCRainbowPrivateKey k = (BCRainbowPrivateKey) key;
            return new RainbowPrivateKeyParameters(k.getInvA1(), k.getB1(), k.getInvA2(), k.getB2(), k.getVi(), k.getLayers());
        }
        throw new InvalidKeyException("can't identify Rainbow private key.");
    }
}
