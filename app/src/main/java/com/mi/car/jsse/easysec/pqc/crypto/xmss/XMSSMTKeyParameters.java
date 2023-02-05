package com.mi.car.jsse.easysec.pqc.crypto.xmss;

import com.mi.car.jsse.easysec.crypto.params.AsymmetricKeyParameter;

public class XMSSMTKeyParameters extends AsymmetricKeyParameter {
    private final String treeDigest;

    public XMSSMTKeyParameters(boolean isPrivateKey, String treeDigest2) {
        super(isPrivateKey);
        this.treeDigest = treeDigest2;
    }

    public String getTreeDigest() {
        return this.treeDigest;
    }
}
