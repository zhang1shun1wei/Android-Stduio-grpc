package com.mi.car.jsse.easysec.crypto.agreement.kdf;

import com.mi.car.jsse.easysec.crypto.DerivationParameters;

public class GSKKDFParameters implements DerivationParameters {
    private final byte[] nonce;
    private final int startCounter;
    private final byte[] z;

    public GSKKDFParameters(byte[] z2, int startCounter2) {
        this(z2, startCounter2, null);
    }

    public GSKKDFParameters(byte[] z2, int startCounter2, byte[] nonce2) {
        this.z = z2;
        this.startCounter = startCounter2;
        this.nonce = nonce2;
    }

    public byte[] getZ() {
        return this.z;
    }

    public int getStartCounter() {
        return this.startCounter;
    }

    public byte[] getNonce() {
        return this.nonce;
    }
}
