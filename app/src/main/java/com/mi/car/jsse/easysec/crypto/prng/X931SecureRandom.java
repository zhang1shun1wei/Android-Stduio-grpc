package com.mi.car.jsse.easysec.crypto.prng;

import java.security.SecureRandom;

public class X931SecureRandom extends SecureRandom {
    private final X931RNG drbg;
    private final boolean predictionResistant;
    private final SecureRandom randomSource;

    X931SecureRandom(SecureRandom randomSource2, X931RNG drbg2, boolean predictionResistant2) {
        this.randomSource = randomSource2;
        this.drbg = drbg2;
        this.predictionResistant = predictionResistant2;
    }

    @Override // java.security.SecureRandom
    public void setSeed(byte[] seed) {
        synchronized (this) {
            if (this.randomSource != null) {
                this.randomSource.setSeed(seed);
            }
        }
    }

    @Override // java.security.SecureRandom
    public void setSeed(long seed) {
        synchronized (this) {
            if (this.randomSource != null) {
                this.randomSource.setSeed(seed);
            }
        }
    }

    public void nextBytes(byte[] bytes) {
        synchronized (this) {
            if (this.drbg.generate(bytes, this.predictionResistant) < 0) {
                this.drbg.reseed();
                this.drbg.generate(bytes, this.predictionResistant);
            }
        }
    }

    public byte[] generateSeed(int numBytes) {
        return EntropyUtil.generateSeed(this.drbg.getEntropySource(), numBytes);
    }
}
