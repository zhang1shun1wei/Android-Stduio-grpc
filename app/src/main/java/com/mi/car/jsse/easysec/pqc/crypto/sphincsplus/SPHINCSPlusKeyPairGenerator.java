package com.mi.car.jsse.easysec.pqc.crypto.sphincsplus;

import com.mi.car.jsse.easysec.crypto.AsymmetricCipherKeyPair;
import com.mi.car.jsse.easysec.crypto.AsymmetricCipherKeyPairGenerator;
import com.mi.car.jsse.easysec.crypto.KeyGenerationParameters;
import com.mi.car.jsse.easysec.crypto.params.AsymmetricKeyParameter;
import java.security.SecureRandom;

public class SPHINCSPlusKeyPairGenerator implements AsymmetricCipherKeyPairGenerator {
    private SPHINCSPlusParameters parameters;
    private SecureRandom random;

    @Override // com.mi.car.jsse.easysec.crypto.AsymmetricCipherKeyPairGenerator
    public void init(KeyGenerationParameters param) {
        this.random = param.getRandom();
        this.parameters = ((SPHINCSPlusKeyGenerationParameters) param).getParameters();
    }

    @Override // com.mi.car.jsse.easysec.crypto.AsymmetricCipherKeyPairGenerator
    public AsymmetricCipherKeyPair generateKeyPair() {
        SPHINCSPlusEngine engine = this.parameters.getEngine();
        SK sk = new SK(sec_rand(engine.N), sec_rand(engine.N));
        byte[] pkSeed = sec_rand(engine.N);
        PK pk = new PK(pkSeed, new HT(engine, sk.seed, pkSeed).htPubKey);
        return new AsymmetricCipherKeyPair((AsymmetricKeyParameter) new SPHINCSPlusPublicKeyParameters(this.parameters, pk), (AsymmetricKeyParameter) new SPHINCSPlusPrivateKeyParameters(this.parameters, sk, pk));
    }

    private byte[] sec_rand(int n) {
        byte[] rv = new byte[n];
        this.random.nextBytes(rv);
        return rv;
    }
}
