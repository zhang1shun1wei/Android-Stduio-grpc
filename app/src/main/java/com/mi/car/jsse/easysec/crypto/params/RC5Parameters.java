package com.mi.car.jsse.easysec.crypto.params;

import com.mi.car.jsse.easysec.crypto.CipherParameters;

public class RC5Parameters implements CipherParameters {
    private byte[] key;
    private int rounds;

    public RC5Parameters(byte[] key2, int rounds2) {
        if (key2.length > 255) {
            throw new IllegalArgumentException("RC5 key length can be no greater than 255");
        }
        this.key = new byte[key2.length];
        this.rounds = rounds2;
        System.arraycopy(key2, 0, this.key, 0, key2.length);
    }

    public byte[] getKey() {
        return this.key;
    }

    public int getRounds() {
        return this.rounds;
    }
}
