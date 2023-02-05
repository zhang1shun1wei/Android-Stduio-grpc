package com.mi.car.jsse.easysec.pqc.crypto.sphincsplus;

import com.mi.car.jsse.easysec.crypto.KeyGenerationParameters;
import java.security.SecureRandom;

public class SPHINCSPlusKeyGenerationParameters extends KeyGenerationParameters {
    private final SPHINCSPlusParameters parameters;

    public SPHINCSPlusKeyGenerationParameters(SecureRandom random, SPHINCSPlusParameters parameters2) {
        super(random, -1);
        this.parameters = parameters2;
    }

    /* access modifiers changed from: package-private */
    public SPHINCSPlusParameters getParameters() {
        return this.parameters;
    }
}
