package com.mi.car.jsse.easysec.pqc.crypto.qtesla;

import com.mi.car.jsse.easysec.crypto.params.AsymmetricKeyParameter;
import com.mi.car.jsse.easysec.util.Arrays;

public final class QTESLAPublicKeyParameters extends AsymmetricKeyParameter {
    private byte[] publicKey;
    private int securityCategory;

    public QTESLAPublicKeyParameters(int securityCategory2, byte[] publicKey2) {
        super(false);
        if (publicKey2.length != QTESLASecurityCategory.getPublicSize(securityCategory2)) {
            throw new IllegalArgumentException("invalid key size for security category");
        }
        this.securityCategory = securityCategory2;
        this.publicKey = Arrays.clone(publicKey2);
    }

    public int getSecurityCategory() {
        return this.securityCategory;
    }

    public byte[] getPublicData() {
        return Arrays.clone(this.publicKey);
    }
}
