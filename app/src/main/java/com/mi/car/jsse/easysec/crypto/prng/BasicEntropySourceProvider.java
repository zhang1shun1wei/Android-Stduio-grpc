package com.mi.car.jsse.easysec.crypto.prng;

import java.security.SecureRandom;

public class BasicEntropySourceProvider implements EntropySourceProvider {
    private final boolean _predictionResistant;
    private final SecureRandom _sr;

    public BasicEntropySourceProvider(SecureRandom random, boolean isPredictionResistant) {
        this._sr = random;
        this._predictionResistant = isPredictionResistant;
    }

    @Override // com.mi.car.jsse.easysec.crypto.prng.EntropySourceProvider
    public EntropySource get(final int bitsRequired) {
        return new EntropySource() {
            /* class com.mi.car.jsse.easysec.crypto.prng.BasicEntropySourceProvider.AnonymousClass1 */

            @Override // com.mi.car.jsse.easysec.crypto.prng.EntropySource
            public boolean isPredictionResistant() {
                return BasicEntropySourceProvider.this._predictionResistant;
            }

            @Override // com.mi.car.jsse.easysec.crypto.prng.EntropySource
            public byte[] getEntropy() {
                if (!(BasicEntropySourceProvider.this._sr instanceof SP800SecureRandom) && !(BasicEntropySourceProvider.this._sr instanceof X931SecureRandom)) {
                    return BasicEntropySourceProvider.this._sr.generateSeed((bitsRequired + 7) / 8);
                }
                byte[] rv = new byte[((bitsRequired + 7) / 8)];
                BasicEntropySourceProvider.this._sr.nextBytes(rv);
                return rv;
            }

            @Override // com.mi.car.jsse.easysec.crypto.prng.EntropySource
            public int entropySize() {
                return bitsRequired;
            }
        };
    }
}
