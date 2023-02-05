package com.mi.car.jsse.easysec.pqc.crypto.cmce;

import com.mi.car.jsse.easysec.crypto.params.AsymmetricKeyParameter;

public class CMCEKeyParameters extends AsymmetricKeyParameter {
    private CMCEParameters params;

    public CMCEKeyParameters(boolean isPrivate, CMCEParameters params2) {
        super(isPrivate);
        this.params = params2;
    }

    public CMCEParameters getParameters() {
        return this.params;
    }
}
