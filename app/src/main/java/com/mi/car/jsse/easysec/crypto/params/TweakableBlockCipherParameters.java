package com.mi.car.jsse.easysec.crypto.params;

import com.mi.car.jsse.easysec.crypto.CipherParameters;
import com.mi.car.jsse.easysec.util.Arrays;

public class TweakableBlockCipherParameters implements CipherParameters {
    private final KeyParameter key;
    private final byte[] tweak;

    public TweakableBlockCipherParameters(KeyParameter key2, byte[] tweak2) {
        this.key = key2;
        this.tweak = Arrays.clone(tweak2);
    }

    public KeyParameter getKey() {
        return this.key;
    }

    public byte[] getTweak() {
        return this.tweak;
    }
}
