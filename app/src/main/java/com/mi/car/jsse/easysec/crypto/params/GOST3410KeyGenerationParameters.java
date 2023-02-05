package com.mi.car.jsse.easysec.crypto.params;

import com.mi.car.jsse.easysec.crypto.KeyGenerationParameters;
import java.security.SecureRandom;

public class GOST3410KeyGenerationParameters extends KeyGenerationParameters {
    private GOST3410Parameters params;

    public GOST3410KeyGenerationParameters(SecureRandom random, GOST3410Parameters params2) {
        super(random, params2.getP().bitLength() - 1);
        this.params = params2;
    }

    public GOST3410Parameters getParameters() {
        return this.params;
    }
}
