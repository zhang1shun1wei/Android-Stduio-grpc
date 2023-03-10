package com.mi.car.jsse.easysec.crypto.params;

import com.mi.car.jsse.easysec.crypto.CipherParameters;

public class KeyParameter implements CipherParameters {
    private byte[] key;

    public KeyParameter(byte[] key2) {
        this(key2, 0, key2.length);
    }

    public KeyParameter(byte[] key2, int keyOff, int keyLen) {
        this.key = new byte[keyLen];
        System.arraycopy(key2, keyOff, this.key, 0, keyLen);
    }

    public byte[] getKey() {
        return this.key;
    }
}
