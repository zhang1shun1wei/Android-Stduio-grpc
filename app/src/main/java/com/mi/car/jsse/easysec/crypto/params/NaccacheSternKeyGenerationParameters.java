package com.mi.car.jsse.easysec.crypto.params;

import com.mi.car.jsse.easysec.crypto.KeyGenerationParameters;
import java.security.SecureRandom;

public class NaccacheSternKeyGenerationParameters extends KeyGenerationParameters {
    private int certainty;
    private int cntSmallPrimes;
    private boolean debug;

    public NaccacheSternKeyGenerationParameters(SecureRandom random, int strength, int certainty2, int cntSmallPrimes2) {
        this(random, strength, certainty2, cntSmallPrimes2, false);
    }

    public NaccacheSternKeyGenerationParameters(SecureRandom random, int strength, int certainty2, int cntSmallPrimes2, boolean debug2) {
        super(random, strength);
        this.debug = false;
        this.certainty = certainty2;
        if (cntSmallPrimes2 % 2 == 1) {
            throw new IllegalArgumentException("cntSmallPrimes must be a multiple of 2");
        } else if (cntSmallPrimes2 < 30) {
            throw new IllegalArgumentException("cntSmallPrimes must be >= 30 for security reasons");
        } else {
            this.cntSmallPrimes = cntSmallPrimes2;
            this.debug = debug2;
        }
    }

    public int getCertainty() {
        return this.certainty;
    }

    public int getCntSmallPrimes() {
        return this.cntSmallPrimes;
    }

    public boolean isDebug() {
        return this.debug;
    }
}
