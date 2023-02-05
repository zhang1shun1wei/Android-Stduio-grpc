package com.mi.car.jsse.easysec.pqc.crypto.lms;

import com.mi.car.jsse.easysec.crypto.AsymmetricCipherKeyPair;
import com.mi.car.jsse.easysec.crypto.AsymmetricCipherKeyPairGenerator;
import com.mi.car.jsse.easysec.crypto.KeyGenerationParameters;
import com.mi.car.jsse.easysec.crypto.params.AsymmetricKeyParameter;
import java.security.SecureRandom;

public class LMSKeyPairGenerator implements AsymmetricCipherKeyPairGenerator {
    LMSKeyGenerationParameters param;

    @Override // com.mi.car.jsse.easysec.crypto.AsymmetricCipherKeyPairGenerator
    public void init(KeyGenerationParameters param2) {
        this.param = (LMSKeyGenerationParameters) param2;
    }

    @Override // com.mi.car.jsse.easysec.crypto.AsymmetricCipherKeyPairGenerator
    public AsymmetricCipherKeyPair generateKeyPair() {
        SecureRandom source = this.param.getRandom();
        byte[] I = new byte[16];
        source.nextBytes(I);
        byte[] rootSecret = new byte[32];
        source.nextBytes(rootSecret);
        LMSPrivateKeyParameters privKey = LMS.generateKeys(this.param.getParameters().getLMSigParam(), this.param.getParameters().getLMOTSParam(), 0, I, rootSecret);
        return new AsymmetricCipherKeyPair((AsymmetricKeyParameter) privKey.getPublicKey(), (AsymmetricKeyParameter) privKey);
    }
}
