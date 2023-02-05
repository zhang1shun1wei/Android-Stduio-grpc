package com.mi.car.jsse.easysec.crypto.params;

import com.mi.car.jsse.easysec.util.Arrays;

public class DSTU4145Parameters extends ECDomainParameters {
    private final byte[] dke;

    public DSTU4145Parameters(ECDomainParameters ecParameters, byte[] dke2) {
        super(ecParameters.getCurve(), ecParameters.getG(), ecParameters.getN(), ecParameters.getH(), ecParameters.getSeed());
        this.dke = Arrays.clone(dke2);
    }

    public byte[] getDKE() {
        return Arrays.clone(this.dke);
    }
}
