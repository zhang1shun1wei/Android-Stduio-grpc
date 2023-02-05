package com.mi.car.jsse.easysec.pqc.crypto.frodo;

import com.mi.car.jsse.easysec.crypto.AsymmetricCipherKeyPair;
import com.mi.car.jsse.easysec.crypto.AsymmetricCipherKeyPairGenerator;
import com.mi.car.jsse.easysec.crypto.KeyGenerationParameters;
import com.mi.car.jsse.easysec.crypto.params.AsymmetricKeyParameter;
import java.security.SecureRandom;

public class FrodoKeyPairGenerator implements AsymmetricCipherKeyPairGenerator {
    private int B;
    private int D;
    private FrodoKeyGenerationParameters frodoParams;
    private int n;
    private SecureRandom random;

    private void initialize(KeyGenerationParameters param) {
        this.frodoParams = (FrodoKeyGenerationParameters) param;
        this.random = param.getRandom();
        this.n = this.frodoParams.getParameters().getN();
        this.D = this.frodoParams.getParameters().getD();
        this.B = this.frodoParams.getParameters().getB();
    }

    private AsymmetricCipherKeyPair genKeyPair() {
        FrodoEngine engine = this.frodoParams.getParameters().getEngine();
        byte[] sk = new byte[engine.getPrivateKeySize()];
        byte[] pk = new byte[engine.getPublicKeySize()];
        engine.kem_keypair(pk, sk, this.random);
        return new AsymmetricCipherKeyPair((AsymmetricKeyParameter) new FrodoPublicKeyParameters(this.frodoParams.getParameters(), pk), (AsymmetricKeyParameter) new FrodoPrivateKeyParameters(this.frodoParams.getParameters(), sk));
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
