package com.mi.car.jsse.easysec.pqc.crypto.xmss;

import com.mi.car.jsse.easysec.crypto.params.AsymmetricKeyParameter;

public class XMSSKeyParameters extends AsymmetricKeyParameter {
    public static final String SHAKE128 = "SHAKE128";
    public static final String SHAKE256 = "SHAKE256";
    public static final String SHA_256 = "SHA-256";
    public static final String SHA_512 = "SHA-512";
    private final String treeDigest;

    public XMSSKeyParameters(boolean isPrivateKey, String treeDigest2) {
        super(isPrivateKey);
        this.treeDigest = treeDigest2;
    }

    public String getTreeDigest() {
        return this.treeDigest;
    }
}
