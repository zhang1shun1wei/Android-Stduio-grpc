package com.mi.car.jsse.easysec.crypto.generators;

import com.mi.car.jsse.easysec.crypto.CipherParameters;
import com.mi.car.jsse.easysec.crypto.CryptoServicesRegistrar;
import com.mi.car.jsse.easysec.crypto.params.ParametersWithRandom;
import com.mi.car.jsse.easysec.crypto.params.RSAKeyParameters;
import com.mi.car.jsse.easysec.crypto.params.RSAPrivateCrtKeyParameters;
import com.mi.car.jsse.easysec.util.BigIntegers;
import java.math.BigInteger;
import java.security.SecureRandom;

public class RSABlindingFactorGenerator {
    private static BigInteger ONE = BigInteger.valueOf(1);
    private static BigInteger ZERO = BigInteger.valueOf(0);
    private RSAKeyParameters key;
    private SecureRandom random;

    public void init(CipherParameters param) {
        if (param instanceof ParametersWithRandom) {
            ParametersWithRandom rParam = (ParametersWithRandom) param;
            this.key = (RSAKeyParameters) rParam.getParameters();
            this.random = rParam.getRandom();
        } else {
            this.key = (RSAKeyParameters) param;
            this.random = CryptoServicesRegistrar.getSecureRandom();
        }
        if (this.key instanceof RSAPrivateCrtKeyParameters) {
            throw new IllegalArgumentException("generator requires RSA public key");
        }
    }

    public BigInteger generateBlindingFactor() {
        if (this.key == null) {
            throw new IllegalStateException("generator not initialised");
        }
        BigInteger m = this.key.getModulus();
        int length = m.bitLength() - 1;
        while (true) {
            BigInteger factor = BigIntegers.createRandomBigInteger(length, this.random);
            BigInteger gcd = factor.gcd(m);
            if (!factor.equals(ZERO) && !factor.equals(ONE) && gcd.equals(ONE)) {
                return factor;
            }
        }
    }
}
