package com.mi.car.jsse.easysec.pqc.crypto.lms;

import com.mi.car.jsse.easysec.crypto.KeyGenerationParameters;
import java.security.SecureRandom;

public class LMSKeyGenerationParameters extends KeyGenerationParameters {
    private final LMSParameters lmsParameters;

    public LMSKeyGenerationParameters(LMSParameters lmsParameters2, SecureRandom random) {
        super(random, LmsUtils.calculateStrength(lmsParameters2));
        this.lmsParameters = lmsParameters2;
    }

    public LMSParameters getParameters() {
        return this.lmsParameters;
    }
}
