package com.mi.car.jsse.easysec.pqc.crypto.mceliece;

import com.mi.car.jsse.easysec.crypto.KeyGenerationParameters;
import java.security.SecureRandom;

public class McElieceCCA2KeyGenerationParameters extends KeyGenerationParameters {
    private McElieceCCA2Parameters params;

    public McElieceCCA2KeyGenerationParameters(SecureRandom random, McElieceCCA2Parameters params2) {
        super(random, 128);
        this.params = params2;
    }

    public McElieceCCA2Parameters getParameters() {
        return this.params;
    }
}
