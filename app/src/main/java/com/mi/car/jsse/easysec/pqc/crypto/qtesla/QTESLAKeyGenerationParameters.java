package com.mi.car.jsse.easysec.pqc.crypto.qtesla;

import com.mi.car.jsse.easysec.crypto.KeyGenerationParameters;
import java.security.SecureRandom;

public class QTESLAKeyGenerationParameters extends KeyGenerationParameters {
    private final int securityCategory;

    public QTESLAKeyGenerationParameters(int securityCategory2, SecureRandom random) {
        super(random, -1);
        QTESLASecurityCategory.getPrivateSize(securityCategory2);
        this.securityCategory = securityCategory2;
    }

    public int getSecurityCategory() {
        return this.securityCategory;
    }
}
