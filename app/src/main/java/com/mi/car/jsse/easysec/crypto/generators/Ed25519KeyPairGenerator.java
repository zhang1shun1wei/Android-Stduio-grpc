package com.mi.car.jsse.easysec.crypto.generators;

import com.mi.car.jsse.easysec.crypto.AsymmetricCipherKeyPair;
import com.mi.car.jsse.easysec.crypto.AsymmetricCipherKeyPairGenerator;
import com.mi.car.jsse.easysec.crypto.KeyGenerationParameters;
import com.mi.car.jsse.easysec.crypto.params.AsymmetricKeyParameter;
import com.mi.car.jsse.easysec.crypto.params.Ed25519PrivateKeyParameters;
import java.security.SecureRandom;

public class Ed25519KeyPairGenerator implements AsymmetricCipherKeyPairGenerator {
    private SecureRandom random;

    @Override // com.mi.car.jsse.easysec.crypto.AsymmetricCipherKeyPairGenerator
    public void init(KeyGenerationParameters parameters) {
        this.random = parameters.getRandom();
    }

    @Override // com.mi.car.jsse.easysec.crypto.AsymmetricCipherKeyPairGenerator
    public AsymmetricCipherKeyPair generateKeyPair() {
        Ed25519PrivateKeyParameters privateKey = new Ed25519PrivateKeyParameters(this.random);
        return new AsymmetricCipherKeyPair((AsymmetricKeyParameter) privateKey.generatePublicKey(), (AsymmetricKeyParameter) privateKey);
    }
}
