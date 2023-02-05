package com.mi.car.jsse.easysec.crypto.generators;

import com.mi.car.jsse.easysec.crypto.CipherKeyGenerator;
import com.mi.car.jsse.easysec.crypto.KeyGenerationParameters;
import com.mi.car.jsse.easysec.crypto.params.DESParameters;

public class DESKeyGenerator extends CipherKeyGenerator {
    @Override // com.mi.car.jsse.easysec.crypto.CipherKeyGenerator
    public void init(KeyGenerationParameters param) {
        super.init(param);
        if (this.strength == 0 || this.strength == 7) {
            this.strength = 8;
        } else if (this.strength != 8) {
            throw new IllegalArgumentException("DES key must be 64 bits long.");
        }
    }

    @Override // com.mi.car.jsse.easysec.crypto.CipherKeyGenerator
    public byte[] generateKey() {
        byte[] newKey = new byte[8];
        do {
            this.random.nextBytes(newKey);
            DESParameters.setOddParity(newKey);
        } while (DESParameters.isWeakKey(newKey, 0));
        return newKey;
    }
}
