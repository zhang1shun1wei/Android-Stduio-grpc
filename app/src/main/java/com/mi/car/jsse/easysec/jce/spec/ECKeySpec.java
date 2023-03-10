package com.mi.car.jsse.easysec.jce.spec;

import java.security.spec.KeySpec;

public class ECKeySpec implements KeySpec {
    private ECParameterSpec spec;

    protected ECKeySpec(ECParameterSpec spec2) {
        this.spec = spec2;
    }

    public ECParameterSpec getParams() {
        return this.spec;
    }
}
