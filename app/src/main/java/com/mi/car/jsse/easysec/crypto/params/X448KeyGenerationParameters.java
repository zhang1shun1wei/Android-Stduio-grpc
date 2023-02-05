package com.mi.car.jsse.easysec.crypto.params;

import com.mi.car.jsse.easysec.crypto.KeyGenerationParameters;
import java.security.SecureRandom;

public class X448KeyGenerationParameters extends KeyGenerationParameters {
    public X448KeyGenerationParameters(SecureRandom random) {
        super(random, 448);
    }
}
