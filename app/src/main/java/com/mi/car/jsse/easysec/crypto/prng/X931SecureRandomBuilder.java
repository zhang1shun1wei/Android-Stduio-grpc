package com.mi.car.jsse.easysec.crypto.prng;

import com.mi.car.jsse.easysec.crypto.BlockCipher;
import com.mi.car.jsse.easysec.crypto.CryptoServicesRegistrar;
import com.mi.car.jsse.easysec.crypto.params.KeyParameter;
import com.mi.car.jsse.easysec.util.Arrays;
import com.mi.car.jsse.easysec.util.Pack;
import java.security.SecureRandom;

public class X931SecureRandomBuilder {
    private byte[] dateTimeVector;
    private EntropySourceProvider entropySourceProvider;
    private SecureRandom random;

    public X931SecureRandomBuilder() {
        this(CryptoServicesRegistrar.getSecureRandom(), false);
    }

    public X931SecureRandomBuilder(SecureRandom entropySource, boolean predictionResistant) {
        this.random = entropySource;
        this.entropySourceProvider = new BasicEntropySourceProvider(this.random, predictionResistant);
    }

    public X931SecureRandomBuilder(EntropySourceProvider entropySourceProvider2) {
        this.random = null;
        this.entropySourceProvider = entropySourceProvider2;
    }

    public X931SecureRandomBuilder setDateTimeVector(byte[] dateTimeVector2) {
        this.dateTimeVector = Arrays.clone(dateTimeVector2);
        return this;
    }

    public X931SecureRandom build(BlockCipher engine, KeyParameter key, boolean predictionResistant) {
        if (this.dateTimeVector == null) {
            this.dateTimeVector = new byte[engine.getBlockSize()];
            Pack.longToBigEndian(System.currentTimeMillis(), this.dateTimeVector, 0);
        }
        engine.init(true, key);
        return new X931SecureRandom(this.random, new X931RNG(engine, this.dateTimeVector, this.entropySourceProvider.get(engine.getBlockSize() * 8)), predictionResistant);
    }
}
