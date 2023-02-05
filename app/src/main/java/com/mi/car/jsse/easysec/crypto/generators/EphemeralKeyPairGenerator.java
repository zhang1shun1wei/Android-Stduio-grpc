package com.mi.car.jsse.easysec.crypto.generators;

import com.mi.car.jsse.easysec.crypto.AsymmetricCipherKeyPairGenerator;
import com.mi.car.jsse.easysec.crypto.EphemeralKeyPair;
import com.mi.car.jsse.easysec.crypto.KeyEncoder;

public class EphemeralKeyPairGenerator {
    private AsymmetricCipherKeyPairGenerator gen;
    private KeyEncoder keyEncoder;

    public EphemeralKeyPairGenerator(AsymmetricCipherKeyPairGenerator gen2, KeyEncoder keyEncoder2) {
        this.gen = gen2;
        this.keyEncoder = keyEncoder2;
    }

    public EphemeralKeyPair generate() {
        return new EphemeralKeyPair(this.gen.generateKeyPair(), this.keyEncoder);
    }
}
