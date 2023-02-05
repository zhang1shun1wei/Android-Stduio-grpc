package com.mi.car.jsse.easysec.crypto.params;

import com.mi.car.jsse.easysec.crypto.DerivationParameters;
import com.mi.car.jsse.easysec.util.Arrays;

public final class KDFFeedbackParameters implements DerivationParameters {
    private static final int UNUSED_R = -1;
    private final byte[] fixedInputData;
    private final byte[] iv;
    private final byte[] ki;
    private final int r;
    private final boolean useCounter;

    private KDFFeedbackParameters(byte[] ki2, byte[] iv2, byte[] fixedInputData2, int r2, boolean useCounter2) {
        if (ki2 == null) {
            throw new IllegalArgumentException("A KDF requires Ki (a seed) as input");
        }
        this.ki = Arrays.clone(ki2);
        if (fixedInputData2 == null) {
            this.fixedInputData = new byte[0];
        } else {
            this.fixedInputData = Arrays.clone(fixedInputData2);
        }
        this.r = r2;
        if (iv2 == null) {
            this.iv = new byte[0];
        } else {
            this.iv = Arrays.clone(iv2);
        }
        this.useCounter = useCounter2;
    }

    public static KDFFeedbackParameters createWithCounter(byte[] ki2, byte[] iv2, byte[] fixedInputData2, int r2) {
        if (r2 == 8 || r2 == 16 || r2 == 24 || r2 == 32) {
            return new KDFFeedbackParameters(ki2, iv2, fixedInputData2, r2, true);
        }
        throw new IllegalArgumentException("Length of counter should be 8, 16, 24 or 32");
    }

    public static KDFFeedbackParameters createWithoutCounter(byte[] ki2, byte[] iv2, byte[] fixedInputData2) {
        return new KDFFeedbackParameters(ki2, iv2, fixedInputData2, UNUSED_R, false);
    }

    public byte[] getKI() {
        return this.ki;
    }

    public byte[] getIV() {
        return this.iv;
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
