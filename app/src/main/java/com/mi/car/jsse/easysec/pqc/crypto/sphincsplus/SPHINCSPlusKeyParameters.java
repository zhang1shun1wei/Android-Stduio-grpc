package com.mi.car.jsse.easysec.pqc.crypto.sphincsplus;

import com.mi.car.jsse.easysec.crypto.params.AsymmetricKeyParameter;

public class SPHINCSPlusKeyParameters extends AsymmetricKeyParameter {
    final SPHINCSPlusParameters parameters;

    protected SPHINCSPlusKeyParameters(boolean isPrivate, SPHINCSPlusParameters parameters2) {
        super(isPrivate);
        this.parameters = parameters2;
    }

    public SPHINCSPlusParameters getParameters() {
        return this.parameters;
    }
}
