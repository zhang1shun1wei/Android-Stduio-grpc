package com.mi.car.jsse.easysec.crypto.params;

import com.mi.car.jsse.easysec.crypto.CipherParameters;

public class ParametersWithUKM implements CipherParameters {
    private CipherParameters parameters;
    private byte[] ukm;

    public ParametersWithUKM(CipherParameters parameters2, byte[] ukm2) {
        this(parameters2, ukm2, 0, ukm2.length);
    }

    public ParametersWithUKM(CipherParameters parameters2, byte[] ukm2, int ivOff, int ivLen) {
        this.ukm = new byte[ivLen];
        this.parameters = parameters2;
        System.arraycopy(ukm2, ivOff, this.ukm, 0, ivLen);
    }

    public byte[] getUKM() {
        return this.ukm;
    }

    public CipherParameters getParameters() {
        return this.parameters;
    }
}
