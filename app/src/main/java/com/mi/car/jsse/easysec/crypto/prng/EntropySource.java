package com.mi.car.jsse.easysec.crypto.prng;

public interface EntropySource {
    int entropySize();

    byte[] getEntropy();

    boolean isPredictionResistant();
}
