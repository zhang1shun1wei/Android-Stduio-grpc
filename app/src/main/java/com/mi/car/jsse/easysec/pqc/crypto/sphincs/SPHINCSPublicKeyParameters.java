package com.mi.car.jsse.easysec.pqc.crypto.sphincs;

import com.mi.car.jsse.easysec.util.Arrays;

public class SPHINCSPublicKeyParameters extends SPHINCSKeyParameters {
    private final byte[] keyData;

    public SPHINCSPublicKeyParameters(byte[] keyData2) {
        super(false, null);
        this.keyData = Arrays.clone(keyData2);
    }

    public SPHINCSPublicKeyParameters(byte[] keyData2, String treeDigest) {
        super(false, treeDigest);
        this.keyData = Arrays.clone(keyData2);
    }

    public byte[] getKeyData() {
        return Arrays.clone(this.keyData);
    }
}
