package com.mi.car.jsse.easysec.pqc.crypto.mceliece;

import com.mi.car.jsse.easysec.crypto.KeyGenerationParameters;
import java.security.SecureRandom;

public class McElieceKeyGenerationParameters extends KeyGenerationParameters {
    private McElieceParameters params;

    public McElieceKeyGenerationParameters(SecureRandom random, McElieceParameters params2) {
        super(random, 256);
        this.params = params2;
    }

    public McElieceParameters getParameters() {
        return this.params;
    }
}
