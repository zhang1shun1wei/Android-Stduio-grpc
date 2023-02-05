package com.mi.car.jsse.easysec.crypto.generators;

import com.mi.car.jsse.easysec.crypto.AsymmetricCipherKeyPair;
import com.mi.car.jsse.easysec.crypto.AsymmetricCipherKeyPairGenerator;
import com.mi.car.jsse.easysec.crypto.KeyGenerationParameters;
import com.mi.car.jsse.easysec.crypto.params.AsymmetricKeyParameter;
import com.mi.car.jsse.easysec.crypto.params.Ed448PrivateKeyParameters;
import java.security.SecureRandom;

public class Ed448KeyPairGenerator implements AsymmetricCipherKeyPairGenerator {
    private SecureRandom random;

    @Override // com.mi.car.jsse.easysec.crypto.AsymmetricCipherKeyPairGenerator
    public void init(KeyGenerationParameters parameters) {
        this.random = parameters.getRandom();
    }

    @Override // com.mi.car.jsse.easysec.crypto.AsymmetricCipherKeyPairGenerator
    public AsymmetricCipherKeyPair generateKeyPair() {
        Ed448PrivateKeyParameters privateKey = new Ed448PrivateKeyParameters(this.random);
        return new AsymmetricCipherKeyPair((AsymmetricKeyParameter) privateKey.generatePublicKey(), (AsymmetricKeyParameter) privateKey);
    }
}
