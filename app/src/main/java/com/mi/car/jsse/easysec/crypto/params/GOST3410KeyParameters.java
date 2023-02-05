package com.mi.car.jsse.easysec.crypto.params;

public class GOST3410KeyParameters extends AsymmetricKeyParameter {
    private GOST3410Parameters params;

    public GOST3410KeyParameters(boolean isPrivate, GOST3410Parameters params2) {
        super(isPrivate);
        this.params = params2;
    }

    public GOST3410Parameters getParameters() {
        return this.params;
    }
}
