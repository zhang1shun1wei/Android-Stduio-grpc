package com.mi.car.jsse.easysec.crypto.params;

import com.mi.car.jsse.easysec.crypto.DerivationParameters;
import com.mi.car.jsse.easysec.util.Arrays;

public class HKDFParameters implements DerivationParameters {
    private final byte[] ikm;
    private final byte[] info;
    private final byte[] salt;
    private final boolean skipExpand;

    private HKDFParameters(byte[] ikm2, boolean skip, byte[] salt2, byte[] info2) {
        if (ikm2 == null) {
            throw new IllegalArgumentException("IKM (input keying material) should not be null");
        }
        this.ikm = Arrays.clone(ikm2);
        this.skipExpand = skip;
        if (salt2 == null || salt2.length == 0) {
            this.salt = null;
        } else {
            this.salt = Arrays.clone(salt2);
        }
        if (info2 == null) {
            this.info = new byte[0];
        } else {
            this.info = Arrays.clone(info2);
        }
    }

    public HKDFParameters(byte[] ikm2, byte[] salt2, byte[] info2) {
        this(ikm2, false, salt2, info2);
    }

    public static HKDFParameters skipExtractParameters(byte[] ikm2, byte[] info2) {
        return new HKDFParameters(ikm2, true, null, info2);
    }

    public static HKDFParameters defaultParameters(byte[] ikm2) {
        return new HKDFParameters(ikm2, false, null, null);
    }

    public byte[] getIKM() {
        return Arrays.clone(this.ikm);
    }

    public boolean skipExtract() {
        return this.skipExpand;
    }

    public byte[] getSalt() {
        return Arrays.clone(this.salt);
    }

    public byte[] getInfo() {
        return Arrays.clone(this.info);
    }
}
