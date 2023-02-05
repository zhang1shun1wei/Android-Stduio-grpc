package com.mi.car.jsse.easysec.crypto.generators;

import com.mi.car.jsse.easysec.crypto.AsymmetricCipherKeyPair;
import com.mi.car.jsse.easysec.crypto.AsymmetricCipherKeyPairGenerator;
import com.mi.car.jsse.easysec.crypto.KeyGenerationParameters;
import com.mi.car.jsse.easysec.crypto.params.AsymmetricKeyParameter;
import com.mi.car.jsse.easysec.crypto.params.ECDomainParameters;
import com.mi.car.jsse.easysec.crypto.params.ECKeyGenerationParameters;
import com.mi.car.jsse.easysec.crypto.params.ECPrivateKeyParameters;
import com.mi.car.jsse.easysec.crypto.params.ECPublicKeyParameters;
import com.mi.car.jsse.easysec.math.ec.ECConstants;
import com.mi.car.jsse.easysec.math.ec.ECMultiplier;
import com.mi.car.jsse.easysec.math.ec.FixedPointCombMultiplier;
import com.mi.car.jsse.easysec.math.ec.WNafUtil;
import com.mi.car.jsse.easysec.util.BigIntegers;
import java.math.BigInteger;
import java.security.SecureRandom;

public class ECKeyPairGenerator implements AsymmetricCipherKeyPairGenerator, ECConstants {
    ECDomainParameters params;
    SecureRandom random;

    @Override // com.mi.car.jsse.easysec.crypto.AsymmetricCipherKeyPairGenerator
    public void init(KeyGenerationParameters param) {
        ECKeyGenerationParameters ecP = (ECKeyGenerationParameters) param;
        this.random = ecP.getRandom();
        this.params = ecP.getDomainParameters();
    }

    @Override // com.mi.car.jsse.easysec.crypto.AsymmetricCipherKeyPairGenerator
    public AsymmetricCipherKeyPair generateKeyPair() {
        BigInteger n = this.params.getN();
        int nBitLength = n.bitLength();
        int minWeight = nBitLength >>> 2;
        while (true) {
            BigInteger d = BigIntegers.createRandomBigInteger(nBitLength, this.random);
            if (d.compareTo(ONE) >= 0 && d.compareTo(n) < 0 && WNafUtil.getNafWeight(d) >= minWeight) {
                return new AsymmetricCipherKeyPair((AsymmetricKeyParameter) new ECPublicKeyParameters(createBasePointMultiplier().multiply(this.params.getG(), d), this.params), (AsymmetricKeyParameter) new ECPrivateKeyParameters(d, this.params));
            }
        }
    }

    /* access modifiers changed from: protected */
    public ECMultiplier createBasePointMultiplier() {
        return new FixedPointCombMultiplier();
    }
}
