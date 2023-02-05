package com.mi.car.jsse.easysec.util.test;

import com.mi.car.jsse.easysec.crypto.prng.EntropySource;
import com.mi.car.jsse.easysec.crypto.prng.EntropySourceProvider;
import java.security.SecureRandom;

public class TestRandomEntropySourceProvider implements EntropySourceProvider {
    private final boolean _predictionResistant;
    private final SecureRandom _sr = new SecureRandom();

    public TestRandomEntropySourceProvider(boolean isPredictionResistant) {
        this._predictionResistant = isPredictionResistant;
    }

    @Override // com.mi.car.jsse.easysec.crypto.prng.EntropySourceProvider
    public EntropySource get(final int bitsRequired) {
        return new EntropySource() {
            /* class com.mi.car.jsse.easysec.util.test.TestRandomEntropySourceProvider.AnonymousClass1 */

            @Override // com.mi.car.jsse.easysec.crypto.prng.EntropySource
            public boolean isPredictionResistant() {
                return TestRandomEntropySourceProvider.this._predictionResistant;
            }

            @Override // com.mi.car.jsse.easysec.crypto.prng.EntropySource
            public byte[] getEntropy() {
                byte[] rv = new byte[((bitsRequired + 7) / 8)];
                TestRandomEntropySourceProvider.this._sr.nextBytes(rv);
                return rv;
            }

            @Override // com.mi.car.jsse.easysec.crypto.prng.EntropySource
            public int entropySize() {
                return bitsRequired;
            }
        };
    }
}
