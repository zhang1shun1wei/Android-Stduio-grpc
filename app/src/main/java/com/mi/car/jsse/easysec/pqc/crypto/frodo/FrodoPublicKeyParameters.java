package com.mi.car.jsse.easysec.pqc.crypto.frodo;

import com.mi.car.jsse.easysec.util.Arrays;

public class FrodoPublicKeyParameters extends FrodoKeyParameters {
    public byte[] publicKey;

    public byte[] getPublicKey() {
        return Arrays.clone(this.publicKey);
    }

    public byte[] getEncoded() {
        return getPublicKey();
    }

    public FrodoPublicKeyParameters(FrodoParameters params, byte[] publicKey2) {
        super(false, params);
        this.publicKey = Arrays.clone(publicKey2);
    }
}
