package com.mi.car.jsse.easysec.tls;

public class PRFAlgorithm {
    public static final int ssl_prf_legacy = 0;
    public static final int tls13_hkdf_sha256 = 4;
    public static final int tls13_hkdf_sha384 = 5;
    public static final int tls13_hkdf_sm3 = 7;
    public static final int tls_prf_legacy = 1;
    public static final int tls_prf_sha256 = 2;
    public static final int tls_prf_sha384 = 3;

    public static String getName(int prfAlgorithm) {
        switch (prfAlgorithm) {
            case 0:
                return "ssl_prf_legacy";
            case 1:
                return "tls_prf_legacy";
            case 2:
                return "tls_prf_sha256";
            case 3:
                return "tls_prf_sha384";
            case 4:
                return "tls13_hkdf_sha256";
            case 5:
                return "tls13_hkdf_sha384";
            case 6:
            default:
                return "UNKNOWN";
            case 7:
                return "tls13_hkdf_sm3";
        }
    }

    public static String getText(int prfAlgorithm) {
        return getName(prfAlgorithm) + "(" + prfAlgorithm + ")";
    }
}
