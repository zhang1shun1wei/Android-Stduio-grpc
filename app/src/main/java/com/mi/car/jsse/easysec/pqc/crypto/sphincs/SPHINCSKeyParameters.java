package com.mi.car.jsse.easysec.pqc.crypto.sphincs;

import com.mi.car.jsse.easysec.crypto.params.AsymmetricKeyParameter;

public class SPHINCSKeyParameters extends AsymmetricKeyParameter {
    public static final String SHA3_256 = "SHA3-256";
    public static final String SHA512_256 = "SHA-512/256";
    private final String treeDigest;

    protected SPHINCSKeyParameters(boolean isPrivateKey, String treeDigest2) {
        super(isPrivateKey);
        this.treeDigest = treeDigest2;
    }

    public String getTreeDigest() {
        return this.treeDigest;
    }
}
