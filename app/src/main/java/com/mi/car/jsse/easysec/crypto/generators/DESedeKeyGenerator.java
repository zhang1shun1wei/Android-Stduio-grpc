package com.mi.car.jsse.easysec.crypto.generators;

import com.mi.car.jsse.easysec.crypto.KeyGenerationParameters;
import com.mi.car.jsse.easysec.crypto.params.DESedeParameters;

public class DESedeKeyGenerator extends DESKeyGenerator {
    private static final int MAX_IT = 20;

    public DESedeKeyGenerator() {
    }

    public void init(KeyGenerationParameters param) {
        this.random = param.getRandom();
        this.strength = (param.getStrength() + 7) / 8;
        if (this.strength != 0 && this.strength != 21) {
            if (this.strength == 14) {
                this.strength = 16;
            } else if (this.strength != 24 && this.strength != 16) {
                throw new IllegalArgumentException("DESede key must be 192 or 128 bits long.");
            }
        } else {
            this.strength = 24;
        }

    }

    public byte[] generateKey() {
        byte[] newKey = new byte[this.strength];
        int count = 0;

        do {
            this.random.nextBytes(newKey);
            DESedeParameters.setOddParity(newKey);
            ++count;
        } while(count < 20 && (DESedeParameters.isWeakKey(newKey, 0, newKey.length) || !DESedeParameters.isRealEDEKey(newKey, 0)));

        if (!DESedeParameters.isWeakKey(newKey, 0, newKey.length) && DESedeParameters.isRealEDEKey(newKey, 0)) {
            return newKey;
        } else {
            throw new IllegalStateException("Unable to generate DES-EDE key");
        }
    }
}

