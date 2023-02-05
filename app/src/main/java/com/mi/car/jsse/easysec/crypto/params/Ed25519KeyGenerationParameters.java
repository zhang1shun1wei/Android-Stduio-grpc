package com.mi.car.jsse.easysec.crypto.params;

import com.mi.car.jsse.easysec.crypto.KeyGenerationParameters;
import java.security.SecureRandom;

public class Ed25519KeyGenerationParameters extends KeyGenerationParameters {
    public Ed25519KeyGenerationParameters(SecureRandom random) {
        super(random, 256);
    }
}
