package com.mi.car.jsse.easysec.pqc.crypto.frodo;

import com.mi.car.jsse.easysec.util.Arrays;

public class FrodoPrivateKeyParameters extends FrodoKeyParameters {
    private byte[] privateKey;

    public byte[] getPrivateKey() {
        return Arrays.clone(this.privateKey);
    }

    public FrodoPrivateKeyParameters(FrodoParameters params, byte[] privateKey2) {
        super(true, params);
        this.privateKey = Arrays.clone(privateKey2);
    }

    public byte[] getEncoded() {
        return Arrays.clone(this.privateKey);
    }
}
