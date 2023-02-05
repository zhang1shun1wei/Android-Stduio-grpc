package com.mi.car.jsse.easysec.crypto.params;

import com.mi.car.jsse.easysec.crypto.DerivationParameters;
import com.mi.car.jsse.easysec.util.Arrays;

public final class KDFCounterParameters implements DerivationParameters {
    private byte[] fixedInputDataCounterPrefix;
    private byte[] fixedInputDataCounterSuffix;
    private byte[] ki;
    private int r;

    public KDFCounterParameters(byte[] ki2, byte[] fixedInputDataCounterSuffix2, int r2) {
        this(ki2, null, fixedInputDataCounterSuffix2, r2);
    }

    public KDFCounterParameters(byte[] ki2, byte[] fixedInputDataCounterPrefix2, byte[] fixedInputDataCounterSuffix2, int r2) {
        if (ki2 == null) {
            throw new IllegalArgumentException("A KDF requires Ki (a seed) as input");
        }
        this.ki = Arrays.clone(ki2);
        if (fixedInputDataCounterPrefix2 == null) {
            this.fixedInputDataCounterPrefix = new byte[0];
        } else {
            this.fixedInputDataCounterPrefix = Arrays.clone(fixedInputDataCounterPrefix2);
        }
        if (fixedInputDataCounterSuffix2 == null) {
            this.fixedInputDataCounterSuffix = new byte[0];
        } else {
            this.fixedInputDataCounterSuffix = Arrays.clone(fixedInputDataCounterSuffix2);
        }
        if (r2 == 8 || r2 == 16 || r2 == 24 || r2 == 32) {
            this.r = r2;
            return;
        }
        throw new IllegalArgumentException("Length of counter should be 8, 16, 24 or 32");
    }

    public byte[] getKI() {
        return this.ki;
    }

    public byte[] getFixedInputData() {
        return Arrays.clone(this.fixedInputDataCounterSuffix);
    }

    public byte[] getFixedInputDataCounterPrefix() {
        return Arrays.clone(this.fixedInputDataCounterPrefix);
    }

    public byte[] getFixedInputDataCounterSuffix() {
        return Arrays.clone(this.fixedInputDataCounterSuffix);
    }

    public int getR() {
        return this.r;
    }
}
