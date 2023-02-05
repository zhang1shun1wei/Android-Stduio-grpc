package com.mi.car.jsse.easysec.crypto.generators;

import com.mi.car.jsse.easysec.crypto.AsymmetricCipherKeyPair;
import com.mi.car.jsse.easysec.crypto.AsymmetricCipherKeyPairGenerator;
import com.mi.car.jsse.easysec.crypto.KeyGenerationParameters;
import com.mi.car.jsse.easysec.crypto.params.AsymmetricKeyParameter;
import com.mi.car.jsse.easysec.crypto.params.DSAKeyGenerationParameters;
import com.mi.car.jsse.easysec.crypto.params.DSAParameters;
import com.mi.car.jsse.easysec.crypto.params.DSAPrivateKeyParameters;
import com.mi.car.jsse.easysec.crypto.params.DSAPublicKeyParameters;
import com.mi.car.jsse.easysec.math.ec.WNafUtil;
import com.mi.car.jsse.easysec.util.BigIntegers;
import java.math.BigInteger;
import java.security.SecureRandom;

public class DSAKeyPairGenerator implements AsymmetricCipherKeyPairGenerator {
    private static final BigInteger ONE = BigInteger.valueOf(1);
    private DSAKeyGenerationParameters param;

    @Override // com.mi.car.jsse.easysec.crypto.AsymmetricCipherKeyPairGenerator
    public void init(KeyGenerationParameters param2) {
        this.param = (DSAKeyGenerationParameters) param2;
    }

    @Override // com.mi.car.jsse.easysec.crypto.AsymmetricCipherKeyPairGenerator
    public AsymmetricCipherKeyPair generateKeyPair() {
        DSAParameters dsaParams = this.param.getParameters();
        BigInteger x = generatePrivateKey(dsaParams.getQ(), this.param.getRandom());
        return new AsymmetricCipherKeyPair((AsymmetricKeyParameter) new DSAPublicKeyParameters(calculatePublicKey(dsaParams.getP(), dsaParams.getG(), x), dsaParams), (AsymmetricKeyParameter) new DSAPrivateKeyParameters(x, dsaParams));
    }

    private static BigInteger generatePrivateKey(BigInteger q, SecureRandom random) {
        BigInteger x;
        int minWeight = q.bitLength() >>> 2;
        do {
            x = BigIntegers.createRandomInRange(ONE, q.subtract(ONE), random);
        } while (WNafUtil.getNafWeight(x) < minWeight);
        return x;
    }

    private static BigInteger calculatePublicKey(BigInteger p, BigInteger g, BigInteger x) {
        return g.modPow(x, p);
    }
}
