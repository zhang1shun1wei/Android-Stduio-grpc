package com.mi.car.jsse.easysec.crypto.params;

import com.mi.car.jsse.easysec.crypto.CipherParameters;
import com.mi.car.jsse.easysec.util.Arrays;

public class Blake3Parameters implements CipherParameters {
    private static final int KEYLEN = 32;
    private byte[] theContext;
    private byte[] theKey;

    public static Blake3Parameters context(byte[] pContext) {
        if (pContext == null) {
            throw new IllegalArgumentException("Invalid context");
        }
        Blake3Parameters myParams = new Blake3Parameters();
        myParams.theContext = Arrays.clone(pContext);
        return myParams;
    }

    public static Blake3Parameters key(byte[] pKey) {
        if (pKey == null || pKey.length != 32) {
            throw new IllegalArgumentException("Invalid keyLength");
        }
        Blake3Parameters myParams = new Blake3Parameters();
        myParams.theKey = Arrays.clone(pKey);
        return myParams;
    }

    public byte[] getKey() {
        return Arrays.clone(this.theKey);
    }

    public void clearKey() {
        Arrays.fill(this.theKey, (byte) 0);
    }

    public byte[] getContext() {
        return Arrays.clone(this.theContext);
    }
}
