package com.mi.car.jsse.easysec.pqc.crypto.gmss;

import com.mi.car.jsse.easysec.crypto.params.AsymmetricKeyParameter;

public class GMSSKeyParameters extends AsymmetricKeyParameter {
    private GMSSParameters params;

    public GMSSKeyParameters(boolean isPrivate, GMSSParameters params2) {
        super(isPrivate);
        this.params = params2;
    }

    public GMSSParameters getParameters() {
        return this.params;
    }
}
