package com.mi.car.jsse.easysec.pqc.crypto.qtesla;

public class QTESLASecurityCategory {
    public static final int PROVABLY_SECURE_I = 5;
    public static final int PROVABLY_SECURE_III = 6;

    private QTESLASecurityCategory() {
    }

    static void validate(int securityCategory) {
        switch (securityCategory) {
            case 5:
            case 6:
                return;
            default:
                throw new IllegalArgumentException("unknown security category: " + securityCategory);
        }
    }

    static int getPrivateSize(int securityCategory) {
        switch (securityCategory) {
            case 5:
                return 5224;
            case 6:
                return 12392;
            default:
                throw new IllegalArgumentException("unknown security category: " + securityCategory);
        }
    }

    static int getPublicSize(int securityCategory) {
        switch (securityCategory) {
            case 5:
                return 14880;
            case 6:
                return 38432;
            default:
                throw new IllegalArgumentException("unknown security category: " + securityCategory);
        }
    }

    static int getSignatureSize(int securityCategory) {
        switch (securityCategory) {
            case 5:
                return 2592;
            case 6:
                return 5664;
            default:
                throw new IllegalArgumentException("unknown security category: " + securityCategory);
        }
    }

    public static String getName(int securityCategory) {
        switch (securityCategory) {
            case 5:
                return "qTESLA-p-I";
            case 6:
                return "qTESLA-p-III";
            default:
                throw new IllegalArgumentException("unknown security category: " + securityCategory);
        }
    }
}
