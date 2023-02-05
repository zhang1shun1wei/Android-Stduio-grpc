package com.mi.car.jsse.easysec.pqc.crypto;

import com.mi.car.jsse.easysec.crypto.params.AsymmetricKeyParameter;
import com.mi.car.jsse.easysec.util.Arrays;

public class ExchangePair {
    private final AsymmetricKeyParameter publicKey;
    private final byte[] shared;

    public ExchangePair(AsymmetricKeyParameter publicKey2, byte[] shared2) {
        this.publicKey = publicKey2;
        this.shared = Arrays.clone(shared2);
    }

    public AsymmetricKeyParameter getPublicKey() {
        return this.publicKey;
    }

    public byte[] getSharedValue() {
        return Arrays.clone(this.shared);
    }
}
