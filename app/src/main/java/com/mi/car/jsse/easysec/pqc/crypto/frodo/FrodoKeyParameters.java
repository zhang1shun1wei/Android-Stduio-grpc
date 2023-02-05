package com.mi.car.jsse.easysec.pqc.crypto.frodo;

import com.mi.car.jsse.easysec.crypto.params.AsymmetricKeyParameter;

public class FrodoKeyParameters extends AsymmetricKeyParameter {
    private FrodoParameters params;

    public FrodoKeyParameters(boolean isPrivate, FrodoParameters params2) {
        super(isPrivate);
        this.params = params2;
    }

    public FrodoParameters getParameters() {
        return this.params;
    }
}
