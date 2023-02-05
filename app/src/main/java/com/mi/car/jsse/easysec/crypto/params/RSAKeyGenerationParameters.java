package com.mi.car.jsse.easysec.crypto.params;

import com.mi.car.jsse.easysec.crypto.KeyGenerationParameters;
import java.math.BigInteger;
import java.security.SecureRandom;

public class RSAKeyGenerationParameters extends KeyGenerationParameters {
    private int certainty;
    private BigInteger publicExponent;

    public RSAKeyGenerationParameters(BigInteger publicExponent2, SecureRandom random, int strength, int certainty2) {
        super(random, strength);
        if (strength < 12) {
            throw new IllegalArgumentException("key strength too small");
        } else if (!publicExponent2.testBit(0)) {
            throw new IllegalArgumentException("public exponent cannot be even");
        } else {
            this.publicExponent = publicExponent2;
            this.certainty = certainty2;
        }
    }

    public BigInteger getPublicExponent() {
        return this.publicExponent;
    }

    public int getCertainty() {
        return this.certainty;
    }
}
