package com.mi.car.jsse.easysec.crypto.generators;

import com.mi.car.jsse.easysec.crypto.AsymmetricCipherKeyPair;
import com.mi.car.jsse.easysec.crypto.AsymmetricCipherKeyPairGenerator;
import com.mi.car.jsse.easysec.crypto.KeyGenerationParameters;
import com.mi.car.jsse.easysec.crypto.params.AsymmetricKeyParameter;
import com.mi.car.jsse.easysec.crypto.params.GOST3410KeyGenerationParameters;
import com.mi.car.jsse.easysec.crypto.params.GOST3410Parameters;
import com.mi.car.jsse.easysec.crypto.params.GOST3410PrivateKeyParameters;
import com.mi.car.jsse.easysec.crypto.params.GOST3410PublicKeyParameters;
import com.mi.car.jsse.easysec.math.ec.WNafUtil;
import com.mi.car.jsse.easysec.util.BigIntegers;
import java.math.BigInteger;
import java.security.SecureRandom;

public class GOST3410KeyPairGenerator implements AsymmetricCipherKeyPairGenerator {
    private GOST3410KeyGenerationParameters param;

    @Override // com.mi.car.jsse.easysec.crypto.AsymmetricCipherKeyPairGenerator
    public void init(KeyGenerationParameters param2) {
        this.param = (GOST3410KeyGenerationParameters) param2;
    }

    @Override // com.mi.car.jsse.easysec.crypto.AsymmetricCipherKeyPairGenerator
    public AsymmetricCipherKeyPair generateKeyPair() {
        GOST3410Parameters GOST3410Params = this.param.getParameters();
        SecureRandom random = this.param.getRandom();
        BigInteger q = GOST3410Params.getQ();
        BigInteger p = GOST3410Params.getP();
        BigInteger a = GOST3410Params.getA();
        while (true) {
            BigInteger x = BigIntegers.createRandomBigInteger(256, random);
            if (x.signum() >= 1 && x.compareTo(q) < 0 && WNafUtil.getNafWeight(x) >= 64) {
                return new AsymmetricCipherKeyPair((AsymmetricKeyParameter) new GOST3410PublicKeyParameters(a.modPow(x, p), GOST3410Params), (AsymmetricKeyParameter) new GOST3410PrivateKeyParameters(x, GOST3410Params));
            }
        }
    }
}
