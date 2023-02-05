package com.mi.car.jsse.easysec.pqc.jcajce.spec;

import com.mi.car.jsse.easysec.pqc.crypto.qtesla.QTESLASecurityCategory;
import java.security.spec.AlgorithmParameterSpec;

public class QTESLAParameterSpec implements AlgorithmParameterSpec {
    public static final String PROVABLY_SECURE_I = QTESLASecurityCategory.getName(5);
    public static final String PROVABLY_SECURE_III = QTESLASecurityCategory.getName(6);
    private String securityCategory;

    public QTESLAParameterSpec(String securityCategory2) {
        this.securityCategory = securityCategory2;
    }

    public String getSecurityCategory() {
        return this.securityCategory;
    }
}
