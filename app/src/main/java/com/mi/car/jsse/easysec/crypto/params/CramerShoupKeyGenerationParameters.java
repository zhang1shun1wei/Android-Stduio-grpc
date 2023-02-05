package com.mi.car.jsse.easysec.crypto.params;

import com.mi.car.jsse.easysec.crypto.KeyGenerationParameters;
import java.security.SecureRandom;

public class CramerShoupKeyGenerationParameters extends KeyGenerationParameters {
    private CramerShoupParameters params;

    public CramerShoupKeyGenerationParameters(SecureRandom random, CramerShoupParameters params2) {
        super(random, getStrength(params2));
        this.params = params2;
    }

    public CramerShoupParameters getParameters() {
        return this.params;
    }

    static int getStrength(CramerShoupParameters params2) {
        return params2.getP().bitLength();
    }
}
