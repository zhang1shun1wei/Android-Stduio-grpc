package com.mi.car.jsse.easysec.tls;

public class CertChainType {
    public static final short individual_certs = 0;
    public static final short pkipath = 1;

    public static String getName(short certChainType) {
        switch (certChainType) {
            case 0:
                return "individual_certs";
            case 1:
                return "pkipath";
            default:
                return "UNKNOWN";
        }
    }

    public static String getText(short certChainType) {
        return getName(certChainType) + "(" + ((int) certChainType) + ")";
    }

    public static boolean isValid(short certChainType) {
        return certChainType >= 0 && certChainType <= 1;
    }
}
