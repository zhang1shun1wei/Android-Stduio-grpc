package com.mi.car.jsse.easysec.crypto.params;

import com.mi.car.jsse.easysec.crypto.DerivationParameters;

public class ISO18033KDFParameters implements DerivationParameters {
    byte[] seed;

    public ISO18033KDFParameters(byte[] seed2) {
        this.seed = seed2;
    }

    public byte[] getSeed() {
        return this.seed;
    }
}
