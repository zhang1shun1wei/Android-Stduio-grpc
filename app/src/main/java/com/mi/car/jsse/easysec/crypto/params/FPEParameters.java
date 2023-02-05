package com.mi.car.jsse.easysec.crypto.params;

import com.mi.car.jsse.easysec.crypto.CipherParameters;
import com.mi.car.jsse.easysec.util.Arrays;

public final class FPEParameters implements CipherParameters {
    private final KeyParameter key;
    private final int radix;
    private final byte[] tweak;
    private final boolean useInverse;

    public FPEParameters(KeyParameter key2, int radix2, byte[] tweak2) {
        this(key2, radix2, tweak2, false);
    }

    public FPEParameters(KeyParameter key2, int radix2, byte[] tweak2, boolean useInverse2) {
        this.key = key2;
        this.radix = radix2;
        this.tweak = Arrays.clone(tweak2);
        this.useInverse = useInverse2;
    }

    public KeyParameter getKey() {
        return this.key;
    }

    public int getRadix() {
        return this.radix;
    }

    public byte[] getTweak() {
        return Arrays.clone(this.tweak);
    }

    public boolean isUsingInverseFunction() {
        return this.useInverse;
    }
}
