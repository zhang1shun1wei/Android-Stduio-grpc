package com.mi.car.jsse.easysec.pqc.crypto.saber;

import com.mi.car.jsse.easysec.util.Arrays;

public class SABERPublicKeyParameters extends SABERKeyParameters {
    public byte[] publicKey;

    public byte[] getPublicKey() {
        return Arrays.clone(this.publicKey);
    }

    public byte[] getEncoded() {
        return getPublicKey();
    }

    public SABERPublicKeyParameters(SABERParameters params, byte[] publicKey2) {
        super(false, params);
        this.publicKey = Arrays.clone(publicKey2);
    }
}
