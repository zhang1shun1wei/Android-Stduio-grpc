package com.mi.car.jsse.easysec.crypto.params;

import com.mi.car.jsse.easysec.crypto.KeyGenerationParameters;
import com.mi.car.jsse.easysec.pqc.crypto.rainbow.util.GF2Field;
import java.security.SecureRandom;

public class X25519KeyGenerationParameters extends KeyGenerationParameters {
    public X25519KeyGenerationParameters(SecureRandom random) {
        super(random, GF2Field.MASK);
    }
}
