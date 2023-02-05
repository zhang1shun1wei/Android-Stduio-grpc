package com.mi.car.jsse.easysec.pqc.crypto.cmce;

import com.mi.car.jsse.easysec.util.Arrays;

public class CMCEPublicKeyParameters extends CMCEKeyParameters {
    private final byte[] publicKey;

    public byte[] getPublicKey() {
        return Arrays.clone(this.publicKey);
    }

    public byte[] getEncoded() {
        return getPublicKey();
    }

    public CMCEPublicKeyParameters(CMCEParameters params, byte[] publicKey2) {
        super(false, params);
        this.publicKey = Arrays.clone(publicKey2);
    }
}
