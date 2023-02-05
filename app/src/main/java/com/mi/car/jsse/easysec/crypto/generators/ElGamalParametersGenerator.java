package com.mi.car.jsse.easysec.crypto.generators;

import com.mi.car.jsse.easysec.crypto.params.ElGamalParameters;
import java.math.BigInteger;
import java.security.SecureRandom;

public class ElGamalParametersGenerator {
    private int certainty;
    private SecureRandom random;
    private int size;

    public void init(int size2, int certainty2, SecureRandom random2) {
        this.size = size2;
        this.certainty = certainty2;
        this.random = random2;
    }

    public ElGamalParameters generateParameters() {
        BigInteger[] safePrimes = DHParametersHelper.generateSafePrimes(this.size, this.certainty, this.random);
        BigInteger p = safePrimes[0];
        return new ElGamalParameters(p, DHParametersHelper.selectGenerator(p, safePrimes[1], this.random));
    }
}
