package com.mi.car.jsse.easysec.pqc.jcajce.spec;

import java.security.spec.AlgorithmParameterSpec;

public class LMSHSSParameterSpec implements AlgorithmParameterSpec {
    private final LMSParameterSpec[] specs;

    public LMSHSSParameterSpec(LMSParameterSpec[] specs2) {
        this.specs = (LMSParameterSpec[]) specs2.clone();
    }

    public LMSParameterSpec[] getLMSSpecs() {
        return (LMSParameterSpec[]) this.specs.clone();
    }
}
