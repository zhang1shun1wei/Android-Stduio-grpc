package com.mi.car.jsse.easysec.pqc.crypto.cmce;

import com.mi.car.jsse.easysec.crypto.KeyGenerationParameters;
import java.security.SecureRandom;

public class CMCEKeyGenerationParameters extends KeyGenerationParameters {
    private CMCEParameters params;

    public CMCEKeyGenerationParameters(SecureRandom random, CMCEParameters cmceParams) {
        super(random, 256);
        this.params = cmceParams;
    }

    public CMCEParameters getParameters() {
        return this.params;
    }
}
