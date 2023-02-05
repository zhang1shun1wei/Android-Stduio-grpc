package com.mi.car.jsse.easysec.pqc.crypto.saber;

import com.mi.car.jsse.easysec.crypto.params.AsymmetricKeyParameter;

public class SABERKeyParameters extends AsymmetricKeyParameter {
    private SABERParameters params;

    public SABERKeyParameters(boolean isPrivate, SABERParameters params2) {
        super(isPrivate);
        this.params = params2;
    }

    public SABERParameters getParameters() {
        return this.params;
    }
}
