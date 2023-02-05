package com.mi.car.jsse.easysec.tls;

public class ClientCertificateType {
    public static final short dss_ephemeral_dh_RESERVED = 6;
    public static final short dss_fixed_dh = 4;
    public static final short dss_sign = 2;
    public static final short ecdsa_fixed_ecdh = 66;
    public static final short ecdsa_sign = 64;
    public static final short fortezza_dms_RESERVED = 20;
    public static final short gost_sign256 = 67;
    public static final short gost_sign512 = 68;
    public static final short rsa_ephemeral_dh_RESERVED = 5;
    public static final short rsa_fixed_dh = 3;
    public static final short rsa_fixed_ecdh = 65;
    public static final short rsa_sign = 1;

    public static String getName(short clientCertificateType) {
        switch (clientCertificateType) {
            case 1:
                return "rsa_sign";
            case 2:
                return "dss_sign";
            case 3:
                return "rsa_fixed_dh";
            case 4:
                return "dss_fixed_dh";
            case 5:
                return "rsa_ephemeral_dh_RESERVED";
            case 6:
                return "dss_ephemeral_dh_RESERVED";
            case 20:
                return "fortezza_dms_RESERVED";
            case 64:
                return "ecdsa_sign";
            case 65:
                return "rsa_fixed_ecdh";
            case CipherSuite.TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA:
                return "ecdsa_fixed_ecdh";
            case CipherSuite.TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA:
                return "gost_sign256";
            case CipherSuite.TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA:
                return "gost_sign512";
            default:
                return "UNKNOWN";
        }
    }

    public static String getText(short clientCertificateType) {
        return getName(clientCertificateType) + "(" + ((int) clientCertificateType) + ")";
    }
}
