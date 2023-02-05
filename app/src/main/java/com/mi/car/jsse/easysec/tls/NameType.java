package com.mi.car.jsse.easysec.tls;

public class NameType {
    public static final short host_name = 0;

    public static String getName(short nameType) {
        switch (nameType) {
            case 0:
                return "host_name";
            default:
                return "UNKNOWN";
        }
    }

    public static String getText(short nameType) {
        return getName(nameType) + "(" + ((int) nameType) + ")";
    }

    public static boolean isRecognized(short nameType) {
        return nameType == 0;
    }

    public static boolean isValid(short nameType) {
        return TlsUtils.isValidUint8(nameType);
    }
}
