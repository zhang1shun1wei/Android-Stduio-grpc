package com.mi.car.jsse.easysec.tls;

public class PskKeyExchangeMode {
    public static final short psk_dhe_ke = 1;
    public static final short psk_ke = 0;

    public static String getName(short pskKeyExchangeMode) {
        switch (pskKeyExchangeMode) {
            case 0:
                return "psk_ke";
            case 1:
                return "psk_dhe_ke";
            default:
                return "UNKNOWN";
        }
    }

    public static String getText(short pskKeyExchangeMode) {
        return getName(pskKeyExchangeMode) + "(" + ((int) pskKeyExchangeMode) + ")";
    }
}
