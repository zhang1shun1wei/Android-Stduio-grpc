package com.mi.car.jsse.easysec.crypto.params;

import com.mi.car.jsse.easysec.crypto.CipherParameters;
import com.mi.car.jsse.easysec.crypto.CryptoServicesRegistrar;
import java.security.SecureRandom;

public class ParametersWithRandom implements CipherParameters {
    private CipherParameters parameters;
    private SecureRandom random;

    public ParametersWithRandom(CipherParameters parameters2, SecureRandom random2) {
        this.random = CryptoServicesRegistrar.getSecureRandom(random2);
        this.parameters = parameters2;
    }

    public ParametersWithRandom(CipherParameters parameters2) {
        this(parameters2, null);
    }

    public SecureRandom getRandom() {
        return this.random;
    }

    public CipherParameters getParameters() {
        return this.parameters;
    }
}
