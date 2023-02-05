package com.mi.car.jsse.easysec.crypto.params;

public class CCMParameters extends AEADParameters {
    public CCMParameters(KeyParameter key, int macSize, byte[] nonce, byte[] associatedText) {
        super(key, macSize, nonce, associatedText);
    }
}
