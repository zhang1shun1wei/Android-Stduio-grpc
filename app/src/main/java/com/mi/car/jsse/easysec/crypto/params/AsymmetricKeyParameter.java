package com.mi.car.jsse.easysec.crypto.params;

import com.mi.car.jsse.easysec.crypto.CipherParameters;

public class AsymmetricKeyParameter implements CipherParameters {
    boolean privateKey;

    public AsymmetricKeyParameter(boolean privateKey2) {
        this.privateKey = privateKey2;
    }

    public boolean isPrivate() {
        return this.privateKey;
    }
}
