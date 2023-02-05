package com.mi.car.jsse.easysec.crypto.generators;

import com.mi.car.jsse.easysec.crypto.params.DHParameters;
import com.mi.car.jsse.easysec.crypto.params.DHValidationParameters;
import java.math.BigInteger;
import java.security.SecureRandom;

public class DHParametersGenerator {
    private static final BigInteger TWO = BigInteger.valueOf(2);
    private int certainty;
    private SecureRandom random;
    private int size;

    public void init(int size2, int certainty2, SecureRandom random2) {
        this.size = size2;
        this.certainty = certainty2;
        this.random = random2;
    }

    public DHParameters generateParameters() {
        BigInteger[] safePrimes = DHParametersHelper.generateSafePrimes(this.size, this.certainty, this.random);
        BigInteger p = safePrimes[0];
        BigInteger q = safePrimes[1];
        return new DHParameters(p, DHParametersHelper.selectGenerator(p, q, this.random), q, TWO, (DHValidationParameters) null);
    }
}
