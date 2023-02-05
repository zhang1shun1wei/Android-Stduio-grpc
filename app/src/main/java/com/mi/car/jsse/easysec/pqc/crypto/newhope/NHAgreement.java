package com.mi.car.jsse.easysec.pqc.crypto.newhope;

import com.mi.car.jsse.easysec.crypto.CipherParameters;

public class NHAgreement {
    private NHPrivateKeyParameters privKey;

    public void init(CipherParameters param) {
        this.privKey = (NHPrivateKeyParameters) param;
    }

    public byte[] calculateAgreement(CipherParameters otherPublicKey) {
        byte[] sharedValue = new byte[32];
        NewHope.sharedA(sharedValue, this.privKey.secData, ((NHPublicKeyParameters) otherPublicKey).pubData);
        return sharedValue;
    }
}
