package com.mi.car.jsse.easysec.tls;

public class CachedInformationType {
    public static final short cert = 1;
    public static final short cert_req = 2;

    public static String getName(short cachedInformationType) {
        switch (cachedInformationType) {
            case 1:
                return "cert";
            case 2:
                return "cert_req";
            default:
                return "UNKNOWN";
        }
    }

    public static String getText(short cachedInformationType) {
        return getName(cachedInformationType) + "(" + ((int) cachedInformationType) + ")";
    }
}
