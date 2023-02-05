package com.mi.car.jsse.easysec.pqc.crypto.qtesla;

import com.mi.car.jsse.easysec.crypto.params.AsymmetricKeyParameter;
import com.mi.car.jsse.easysec.util.Arrays;

public final class QTESLAPrivateKeyParameters extends AsymmetricKeyParameter {
    private byte[] privateKey;
    private int securityCategory;

    public QTESLAPrivateKeyParameters(int securityCategory2, byte[] privateKey2) {
        super(true);
        if (privateKey2.length != QTESLASecurityCategory.getPrivateSize(securityCategory2)) {
            throw new IllegalArgumentException("invalid key size for security category");
        }
        this.securityCategory = securityCategory2;
        this.privateKey = Arrays.clone(privateKey2);
    }

    public int getSecurityCategory() {
        return this.securityCategory;
    }

    public byte[] getSecret() {
        return Arrays.clone(this.privateKey);
    }
}
