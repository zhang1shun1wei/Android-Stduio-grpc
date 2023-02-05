package com.mi.car.jsse.easysec.crypto.generators;

import com.mi.car.jsse.easysec.crypto.AsymmetricCipherKeyPair;
import com.mi.car.jsse.easysec.crypto.AsymmetricCipherKeyPairGenerator;
import com.mi.car.jsse.easysec.crypto.KeyGenerationParameters;
import com.mi.car.jsse.easysec.crypto.params.AsymmetricKeyParameter;
import com.mi.car.jsse.easysec.crypto.params.DHParameters;
import com.mi.car.jsse.easysec.crypto.params.ElGamalKeyGenerationParameters;
import com.mi.car.jsse.easysec.crypto.params.ElGamalParameters;
import com.mi.car.jsse.easysec.crypto.params.ElGamalPrivateKeyParameters;
import com.mi.car.jsse.easysec.crypto.params.ElGamalPublicKeyParameters;
import java.math.BigInteger;

public class ElGamalKeyPairGenerator implements AsymmetricCipherKeyPairGenerator {
    private ElGamalKeyGenerationParameters param;

    @Override // com.mi.car.jsse.easysec.crypto.AsymmetricCipherKeyPairGenerator
    public void init(KeyGenerationParameters param2) {
        this.param = (ElGamalKeyGenerationParameters) param2;
    }

    @Override // com.mi.car.jsse.easysec.crypto.AsymmetricCipherKeyPairGenerator
    public AsymmetricCipherKeyPair generateKeyPair() {
        DHKeyGeneratorHelper helper = DHKeyGeneratorHelper.INSTANCE;
        ElGamalParameters egp = this.param.getParameters();
        DHParameters dhp = new DHParameters(egp.getP(), egp.getG(), null, egp.getL());
        BigInteger x = helper.calculatePrivate(dhp, this.param.getRandom());
        return new AsymmetricCipherKeyPair((AsymmetricKeyParameter) new ElGamalPublicKeyParameters(helper.calculatePublic(dhp, x), egp), (AsymmetricKeyParameter) new ElGamalPrivateKeyParameters(x, egp));
    }
}
