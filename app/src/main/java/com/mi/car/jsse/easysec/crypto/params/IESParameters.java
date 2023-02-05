package com.mi.car.jsse.easysec.crypto.params;

import com.mi.car.jsse.easysec.crypto.CipherParameters;
import com.mi.car.jsse.easysec.util.Arrays;

public class IESParameters implements CipherParameters {
    private byte[] derivation;
    private byte[] encoding;
    private int macKeySize;

    public IESParameters(byte[] derivation2, byte[] encoding2, int macKeySize2) {
        this.derivation = Arrays.clone(derivation2);
        this.encoding = Arrays.clone(encoding2);
        this.macKeySize = macKeySize2;
    }

    public byte[] getDerivationV() {
        return Arrays.clone(this.derivation);
    }

    public byte[] getEncodingV() {
        return Arrays.clone(this.encoding);
    }

    public int getMacKeySize() {
        return this.macKeySize;
    }
}
