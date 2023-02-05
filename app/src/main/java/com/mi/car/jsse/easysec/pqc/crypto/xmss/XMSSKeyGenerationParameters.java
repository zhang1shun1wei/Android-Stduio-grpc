package com.mi.car.jsse.easysec.pqc.crypto.xmss;

import com.mi.car.jsse.easysec.crypto.KeyGenerationParameters;
import java.security.SecureRandom;

public final class XMSSKeyGenerationParameters extends KeyGenerationParameters {
    private final XMSSParameters xmssParameters;

    public XMSSKeyGenerationParameters(XMSSParameters xmssParameters2, SecureRandom prng) {
        super(prng, -1);
        this.xmssParameters = xmssParameters2;
    }

    public XMSSParameters getParameters() {
        return this.xmssParameters;
    }
}
