package com.mi.car.jsse.easysec.crypto.params;

public class IESWithCipherParameters extends IESParameters {
    private int cipherKeySize;

    public IESWithCipherParameters(byte[] derivation, byte[] encoding, int macKeySize, int cipherKeySize2) {
        super(derivation, encoding, macKeySize);
        this.cipherKeySize = cipherKeySize2;
    }

    public int getCipherKeySize() {
        return this.cipherKeySize;
    }
}
