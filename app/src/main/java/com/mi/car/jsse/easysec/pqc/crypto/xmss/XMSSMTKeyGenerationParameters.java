package com.mi.car.jsse.easysec.pqc.crypto.xmss;

import com.mi.car.jsse.easysec.crypto.KeyGenerationParameters;
import java.security.SecureRandom;

public final class XMSSMTKeyGenerationParameters extends KeyGenerationParameters {
    private final XMSSMTParameters xmssmtParameters;

    public XMSSMTKeyGenerationParameters(XMSSMTParameters xmssmtParameters2, SecureRandom prng) {
        super(prng, -1);
        this.xmssmtParameters = xmssmtParameters2;
    }

    public XMSSMTParameters getParameters() {
        return this.xmssmtParameters;
    }
}
