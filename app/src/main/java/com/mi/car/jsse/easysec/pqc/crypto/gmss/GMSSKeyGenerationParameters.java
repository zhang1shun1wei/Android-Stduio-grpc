package com.mi.car.jsse.easysec.pqc.crypto.gmss;

import com.mi.car.jsse.easysec.crypto.KeyGenerationParameters;
import java.security.SecureRandom;

public class GMSSKeyGenerationParameters extends KeyGenerationParameters {
    private GMSSParameters params;

    public GMSSKeyGenerationParameters(SecureRandom random, GMSSParameters params2) {
        super(random, 1);
        this.params = params2;
    }

    public GMSSParameters getParameters() {
        return this.params;
    }
}
