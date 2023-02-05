package com.mi.car.jsse.easysec.pqc.crypto.lms;

import com.mi.car.jsse.easysec.crypto.AsymmetricCipherKeyPair;
import com.mi.car.jsse.easysec.crypto.AsymmetricCipherKeyPairGenerator;
import com.mi.car.jsse.easysec.crypto.KeyGenerationParameters;
import com.mi.car.jsse.easysec.crypto.params.AsymmetricKeyParameter;

public class HSSKeyPairGenerator implements AsymmetricCipherKeyPairGenerator {
    HSSKeyGenerationParameters param;

    @Override // com.mi.car.jsse.easysec.crypto.AsymmetricCipherKeyPairGenerator
    public void init(KeyGenerationParameters param2) {
        this.param = (HSSKeyGenerationParameters) param2;
    }

    @Override // com.mi.car.jsse.easysec.crypto.AsymmetricCipherKeyPairGenerator
    public AsymmetricCipherKeyPair generateKeyPair() {
        HSSPrivateKeyParameters privKey = HSS.generateHSSKeyPair(this.param);
        return new AsymmetricCipherKeyPair((AsymmetricKeyParameter) privKey.getPublicKey(), (AsymmetricKeyParameter) privKey);
    }
}
