package com.mi.car.jsse.easysec.crypto.params;

import com.mi.car.jsse.easysec.crypto.KeyGenerationParameters;
import java.security.SecureRandom;

public class ElGamalKeyGenerationParameters extends KeyGenerationParameters {
    private ElGamalParameters params;

    public ElGamalKeyGenerationParameters(SecureRandom random, ElGamalParameters params2) {
        super(random, getStrength(params2));
        this.params = params2;
    }

    public ElGamalParameters getParameters() {
        return this.params;
    }

    static int getStrength(ElGamalParameters params2) {
        return params2.getL() != 0 ? params2.getL() : params2.getP().bitLength();
    }
}
