package com.mi.car.jsse.easysec.pqc.crypto.frodo;

import com.mi.car.jsse.easysec.crypto.KeyGenerationParameters;
import java.security.SecureRandom;

public class FrodoKeyGenerationParameters extends KeyGenerationParameters {
    private FrodoParameters params;

    public FrodoKeyGenerationParameters(SecureRandom random, FrodoParameters frodoParameters) {
        super(random, 256);
        this.params = frodoParameters;
    }

    public FrodoParameters getParameters() {
        return this.params;
    }
}
