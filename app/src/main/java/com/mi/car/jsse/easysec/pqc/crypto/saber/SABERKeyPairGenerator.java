package com.mi.car.jsse.easysec.pqc.crypto.saber;

import com.mi.car.jsse.easysec.crypto.AsymmetricCipherKeyPair;
import com.mi.car.jsse.easysec.crypto.AsymmetricCipherKeyPairGenerator;
import com.mi.car.jsse.easysec.crypto.KeyGenerationParameters;
import com.mi.car.jsse.easysec.crypto.params.AsymmetricKeyParameter;
import java.security.SecureRandom;

public class SABERKeyPairGenerator implements AsymmetricCipherKeyPairGenerator {
    private int l;
    private SecureRandom random;
    private SABERKeyGenerationParameters saberParams;

    private void initialize(KeyGenerationParameters param) {
        this.saberParams = (SABERKeyGenerationParameters) param;
        this.random = param.getRandom();
        this.l = this.saberParams.getParameters().getL();
    }

    private AsymmetricCipherKeyPair genKeyPair() {
        SABEREngine engine = this.saberParams.getParameters().getEngine();
        byte[] sk = new byte[engine.getPrivateKeySize()];
        byte[] pk = new byte[engine.getPublicKeySize()];
        engine.crypto_kem_keypair(pk, sk, this.random);
        return new AsymmetricCipherKeyPair((AsymmetricKeyParameter) new SABERPublicKeyParameters(this.saberParams.getParameters(), pk), (AsymmetricKeyParameter) new SABERPrivateKeyParameters(this.saberParams.getParameters(), sk));
    }

    @Override // com.mi.car.jsse.easysec.crypto.AsymmetricCipherKeyPairGenerator
    public void init(KeyGenerationParameters param) {
        initialize(param);
    }

    @Override // com.mi.car.jsse.easysec.crypto.AsymmetricCipherKeyPairGenerator
    public AsymmetricCipherKeyPair generateKeyPair() {
        return genKeyPair();
    }
}
