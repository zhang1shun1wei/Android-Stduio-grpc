package com.mi.car.jsse.easysec.crypto.params;

import com.mi.car.jsse.easysec.crypto.DerivationParameters;

public class KDFParameters implements DerivationParameters {
    byte[] iv;
    byte[] shared;

    public KDFParameters(byte[] shared2, byte[] iv2) {
        this.shared = shared2;
        this.iv = iv2;
    }

    public byte[] getSharedSecret() {
        return this.shared;
    }

    public byte[] getIV() {
        return this.iv;
    }
}
