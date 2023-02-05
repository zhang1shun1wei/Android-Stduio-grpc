package com.mi.car.jsse.easysec.crypto.params;

import com.mi.car.jsse.easysec.crypto.CipherParameters;

public class ParametersWithSBox implements CipherParameters {
    private CipherParameters parameters;
    private byte[] sBox;

    public ParametersWithSBox(CipherParameters parameters2, byte[] sBox2) {
        this.parameters = parameters2;
        this.sBox = sBox2;
    }

    public byte[] getSBox() {
        return this.sBox;
    }

    public CipherParameters getParameters() {
        return this.parameters;
    }
}
