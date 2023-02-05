package com.mi.car.jsse.easysec.crypto.params;

import com.mi.car.jsse.easysec.crypto.DerivationParameters;
import com.mi.car.jsse.easysec.util.Arrays;

public final class KDFDoublePipelineIterationParameters implements DerivationParameters {
    private static final int UNUSED_R = 32;
    private final byte[] fixedInputData;
    private final byte[] ki;
    private final int r;
    private final boolean useCounter;

    private KDFDoublePipelineIterationParameters(byte[] ki2, byte[] fixedInputData2, int r2, boolean useCounter2) {
        if (ki2 == null) {
            throw new IllegalArgumentException("A KDF requires Ki (a seed) as input");
        }
        this.ki = Arrays.clone(ki2);
        if (fixedInputData2 == null) {
            this.fixedInputData = new byte[0];
        } else {
            this.fixedInputData = Arrays.clone(fixedInputData2);
        }
        if (r2 == 8 || r2 == 16 || r2 == 24 || r2 == 32) {
            this.r = r2;
            this.useCounter = useCounter2;
            return;
        }
        throw new IllegalArgumentException("Length of counter should be 8, 16, 24 or 32");
    }

    public static KDFDoublePipelineIterationParameters createWithCounter(byte[] ki2, byte[] fixedInputData2, int r2) {
        return new KDFDoublePipelineIterationParameters(ki2, fixedInputData2, r2, true);
    }

    public static KDFDoublePipelineIterationParameters createWithoutCounter(byte[] ki2, byte[] fixedInputData2) {
        return new KDFDoublePipelineIterationParameters(ki2, fixedInputData2, 32, false);
    }

    public byte[] getKI() {
        return this.ki;
    }

    public boolean useCounter() {
        return this.useCounter;
    }

    public int getR() {
        return this.r;
    }

    public byte[] getFixedInputData() {
        return Arrays.clone(this.fixedInputData);
    }
}
