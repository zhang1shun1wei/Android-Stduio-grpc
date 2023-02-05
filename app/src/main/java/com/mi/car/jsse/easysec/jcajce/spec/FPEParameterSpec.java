//
// Source code recreated from a .class file by IntelliJ IDEA
// (powered by FernFlower decompiler)
//

package com.mi.car.jsse.easysec.jcajce.spec;

import com.mi.car.jsse.easysec.util.Arrays;
import java.security.spec.AlgorithmParameterSpec;

public class FPEParameterSpec implements AlgorithmParameterSpec {
    private final int radix;
    private final byte[] tweak;
    private final boolean useInverse;

    public FPEParameterSpec(int radix, byte[] tweak) {
        this(radix, tweak, false);
    }

    public FPEParameterSpec(int radix, byte[] tweak, boolean useInverse) {
        this.radix = radix;
        this.tweak = Arrays.clone(tweak);
        this.useInverse = useInverse;
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