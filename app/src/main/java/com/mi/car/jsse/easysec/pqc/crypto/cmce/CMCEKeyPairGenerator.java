package com.mi.car.jsse.easysec.pqc.crypto.cmce;

import com.mi.car.jsse.easysec.crypto.AsymmetricCipherKeyPair;
import com.mi.car.jsse.easysec.crypto.AsymmetricCipherKeyPairGenerator;
import com.mi.car.jsse.easysec.crypto.KeyGenerationParameters;
import com.mi.car.jsse.easysec.crypto.params.AsymmetricKeyParameter;
import java.security.SecureRandom;

public class CMCEKeyPairGenerator implements AsymmetricCipherKeyPairGenerator {
    private CMCEKeyGenerationParameters cmceParams;
    private int m;
    private int n;
    private SecureRandom random;
    private int t;

    private void initialize(KeyGenerationParameters param) {
        this.cmceParams = (CMCEKeyGenerationParameters) param;
        this.random = param.getRandom();
        this.m = this.cmceParams.getParameters().getM();
        this.n = this.cmceParams.getParameters().getN();
        this.t = this.cmceParams.getParameters().getT();
    }

    private AsymmetricCipherKeyPair genKeyPair() {
        CMCEEngine engine = this.cmceParams.getParameters().getEngine();
        byte[] sk = new byte[engine.getPrivateKeySize()];
        byte[] pk = new byte[engine.getPublicKeySize()];
        engine.kem_keypair(pk, sk, this.random);
        return new AsymmetricCipherKeyPair((AsymmetricKeyParameter) new CMCEPublicKeyParameters(this.cmceParams.getParameters(), pk), (AsymmetricKeyParameter) new CMCEPrivateKeyParameters(this.cmceParams.getParameters(), sk));
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
