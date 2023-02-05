package com.mi.car.jsse.easysec.jce.spec;

import java.security.spec.AlgorithmParameterSpec;

public class ElGamalGenParameterSpec implements AlgorithmParameterSpec {
    private int primeSize;

    public ElGamalGenParameterSpec(int primeSize2) {
        this.primeSize = primeSize2;
    }

    public int getPrimeSize() {
        return this.primeSize;
    }
}
