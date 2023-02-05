package com.mi.car.jsse.easysec.tls;

public class KeyUpdateRequest {
    public static final short update_not_requested = 0;
    public static final short update_requested = 1;

    public static String getName(short keyUpdateRequest) {
        switch (keyUpdateRequest) {
            case 0:
                return "update_not_requested";
            case 1:
                return "update_requested";
            default:
                return "UNKNOWN";
        }
    }

    public static String getText(short keyUpdateRequest) {
        return getName(keyUpdateRequest) + "(" + ((int) keyUpdateRequest) + ")";
    }

    public static boolean isValid(short keyUpdateRequest) {
        return keyUpdateRequest >= 0 && keyUpdateRequest <= 1;
    }
}
