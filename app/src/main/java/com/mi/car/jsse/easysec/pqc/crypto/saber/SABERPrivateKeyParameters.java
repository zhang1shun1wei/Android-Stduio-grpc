package com.mi.car.jsse.easysec.pqc.crypto.saber;

import com.mi.car.jsse.easysec.util.Arrays;

public class SABERPrivateKeyParameters extends SABERKeyParameters {
    private byte[] privateKey;

    public byte[] getPrivateKey() {
        return Arrays.clone(this.privateKey);
    }

    public SABERPrivateKeyParameters(SABERParameters params, byte[] privateKey2) {
        super(true, params);
        this.privateKey = Arrays.clone(privateKey2);
    }

    public byte[] getEncoded() {
        return Arrays.clone(this.privateKey);
    }
}
