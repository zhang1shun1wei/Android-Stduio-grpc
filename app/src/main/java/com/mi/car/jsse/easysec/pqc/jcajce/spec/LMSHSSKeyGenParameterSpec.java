package com.mi.car.jsse.easysec.pqc.jcajce.spec;

import java.security.spec.AlgorithmParameterSpec;

public class LMSHSSKeyGenParameterSpec implements AlgorithmParameterSpec {
    private final LMSKeyGenParameterSpec[] specs;

    public LMSHSSKeyGenParameterSpec(LMSKeyGenParameterSpec... specs2) {
        if (specs2.length == 0) {
            throw new IllegalArgumentException("at least one LMSKeyGenParameterSpec required");
        }
        this.specs = (LMSKeyGenParameterSpec[]) specs2.clone();
    }

    public LMSKeyGenParameterSpec[] getLMSSpecs() {
        return (LMSKeyGenParameterSpec[]) this.specs.clone();
    }
}
