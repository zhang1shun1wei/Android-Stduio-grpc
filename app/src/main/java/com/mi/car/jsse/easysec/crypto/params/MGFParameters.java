package com.mi.car.jsse.easysec.crypto.params;

import com.mi.car.jsse.easysec.crypto.DerivationParameters;

public class MGFParameters implements DerivationParameters {
    byte[] seed;

    public MGFParameters(byte[] seed2) {
        this(seed2, 0, seed2.length);
    }

    public MGFParameters(byte[] seed2, int off, int len) {
        this.seed = new byte[len];
        System.arraycopy(seed2, off, this.seed, 0, len);
    }

    public byte[] getSeed() {
        return this.seed;
    }
}
