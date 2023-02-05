package com.mi.car.jsse.easysec.jce.spec;

import com.mi.car.jsse.easysec.util.Arrays;
import java.security.spec.AlgorithmParameterSpec;

public class IESParameterSpec implements AlgorithmParameterSpec {
    private int cipherKeySize;
    private byte[] derivation;
    private byte[] encoding;
    private int macKeySize;
    private byte[] nonce;
    private boolean usePointCompression;

    public IESParameterSpec(byte[] derivation2, byte[] encoding2, int macKeySize2) {
        this(derivation2, encoding2, macKeySize2, -1, null, false);
    }

    public IESParameterSpec(byte[] derivation2, byte[] encoding2, int macKeySize2, int cipherKeySize2, byte[] nonce2) {
        this(derivation2, encoding2, macKeySize2, cipherKeySize2, nonce2, false);
    }

    public IESParameterSpec(byte[] derivation2, byte[] encoding2, int macKeySize2, int cipherKeySize2, byte[] nonce2, boolean usePointCompression2) {
        if (derivation2 != null) {
            this.derivation = new byte[derivation2.length];
            System.arraycopy(derivation2, 0, this.derivation, 0, derivation2.length);
        } else {
            this.derivation = null;
        }
        if (encoding2 != null) {
            this.encoding = new byte[encoding2.length];
            System.arraycopy(encoding2, 0, this.encoding, 0, encoding2.length);
        } else {
            this.encoding = null;
        }
        this.macKeySize = macKeySize2;
        this.cipherKeySize = cipherKeySize2;
        this.nonce = Arrays.clone(nonce2);
        this.usePointCompression = usePointCompression2;
    }

    public byte[] getDerivationV() {
        return Arrays.clone(this.derivation);
    }

    public byte[] getEncodingV() {
        return Arrays.clone(this.encoding);
    }

    public int getMacKeySize() {
        return this.macKeySize;
    }

    public int getCipherKeySize() {
        return this.cipherKeySize;
    }

    public byte[] getNonce() {
        return Arrays.clone(this.nonce);
    }

    public void setPointCompression(boolean usePointCompression2) {
        this.usePointCompression = usePointCompression2;
    }

    public boolean getPointCompression() {
        return this.usePointCompression;
    }
}
