package com.mi.car.jsse.easysec.pqc.crypto.sphincs;

import com.mi.car.jsse.easysec.util.Arrays;

public class SPHINCSPrivateKeyParameters extends SPHINCSKeyParameters {
    private final byte[] keyData;

    public SPHINCSPrivateKeyParameters(byte[] keyData2) {
        super(true, null);
        this.keyData = Arrays.clone(keyData2);
    }

    public SPHINCSPrivateKeyParameters(byte[] keyData2, String treeDigest) {
        super(true, treeDigest);
        this.keyData = Arrays.clone(keyData2);
    }

    public byte[] getKeyData() {
        return Arrays.clone(this.keyData);
    }
}
