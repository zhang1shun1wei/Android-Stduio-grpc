package com.mi.car.jsse.easysec.pqc.crypto.ntru;

import com.mi.car.jsse.easysec.crypto.params.AsymmetricKeyParameter;

public class NTRUEncryptionKeyParameters extends AsymmetricKeyParameter {
    protected final NTRUEncryptionParameters params;

    public NTRUEncryptionKeyParameters(boolean privateKey, NTRUEncryptionParameters params2) {
        super(privateKey);
        this.params = params2;
    }

    public NTRUEncryptionParameters getParameters() {
        return this.params;
    }
}
