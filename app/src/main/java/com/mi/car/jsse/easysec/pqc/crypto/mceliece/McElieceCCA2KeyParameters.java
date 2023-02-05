package com.mi.car.jsse.easysec.pqc.crypto.mceliece;

import com.mi.car.jsse.easysec.crypto.params.AsymmetricKeyParameter;

public class McElieceCCA2KeyParameters extends AsymmetricKeyParameter {
    private String params;

    public McElieceCCA2KeyParameters(boolean isPrivate, String params2) {
        super(isPrivate);
        this.params = params2;
    }

    public String getDigest() {
        return this.params;
    }
}
