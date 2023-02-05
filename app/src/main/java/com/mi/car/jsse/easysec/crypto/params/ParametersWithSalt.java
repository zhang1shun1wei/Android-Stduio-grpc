package com.mi.car.jsse.easysec.crypto.params;

import com.mi.car.jsse.easysec.crypto.CipherParameters;

public class ParametersWithSalt implements CipherParameters {
    private CipherParameters parameters;
    private byte[] salt;

    public ParametersWithSalt(CipherParameters parameters2, byte[] salt2) {
        this(parameters2, salt2, 0, salt2.length);
    }

    public ParametersWithSalt(CipherParameters parameters2, byte[] salt2, int saltOff, int saltLen) {
        this.salt = new byte[saltLen];
        this.parameters = parameters2;
        System.arraycopy(salt2, saltOff, this.salt, 0, saltLen);
    }

    public byte[] getSalt() {
        return this.salt;
    }

    public CipherParameters getParameters() {
        return this.parameters;
    }
}
