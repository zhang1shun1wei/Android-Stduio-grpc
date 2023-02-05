package com.mi.car.jsse.easysec.pqc.crypto.lms;

import com.mi.car.jsse.easysec.crypto.KeyGenerationParameters;
import java.security.SecureRandom;

public class HSSKeyGenerationParameters extends KeyGenerationParameters {
    private final LMSParameters[] lmsParameters;

    public HSSKeyGenerationParameters(LMSParameters[] lmsParameters2, SecureRandom random) {
        super(random, LmsUtils.calculateStrength(lmsParameters2[0]));
        if (lmsParameters2.length == 0 || lmsParameters2.length > 8) {
            throw new IllegalArgumentException("lmsParameters length should be between 1 and 8 inclusive");
        }
        this.lmsParameters = lmsParameters2;
    }

    public int getDepth() {
        return this.lmsParameters.length;
    }

    public LMSParameters[] getLmsParameters() {
        return this.lmsParameters;
    }
}
