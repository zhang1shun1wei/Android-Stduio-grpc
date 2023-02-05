package com.mi.car.jsse.easysec.jce.spec;

import java.security.spec.KeySpec;

public class ElGamalKeySpec implements KeySpec {
    private ElGamalParameterSpec spec;

    public ElGamalKeySpec(ElGamalParameterSpec spec2) {
        this.spec = spec2;
    }

    public ElGamalParameterSpec getParams() {
        return this.spec;
    }
}
