package com.mi.car.jsse.easysec.tls;

public class IdentifierType {
    public static final short cert_sha1_hash = 3;
    public static final short key_sha1_hash = 1;
    public static final short pre_agreed = 0;
    public static final short x509_name = 2;

    public static String getName(short identifierType) {
        switch (identifierType) {
            case 0:
                return "pre_agreed";
            case 1:
                return "key_sha1_hash";
            case 2:
                return "x509_name";
            case 3:
                return "cert_sha1_hash";
            default:
                return "UNKNOWN";
        }
    }

    public static String getText(short identifierType) {
        return getName(identifierType) + "(" + ((int) identifierType) + ")";
    }
}
