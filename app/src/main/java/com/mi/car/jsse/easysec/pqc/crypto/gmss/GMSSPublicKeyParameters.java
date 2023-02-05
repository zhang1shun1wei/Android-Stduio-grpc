package com.mi.car.jsse.easysec.pqc.crypto.gmss;

public class GMSSPublicKeyParameters extends GMSSKeyParameters {
    private byte[] gmssPublicKey;

    public GMSSPublicKeyParameters(byte[] key, GMSSParameters gmssParameterSet) {
        super(false, gmssParameterSet);
        this.gmssPublicKey = key;
    }

    public byte[] getPublicKey() {
        return this.gmssPublicKey;
    }
}
