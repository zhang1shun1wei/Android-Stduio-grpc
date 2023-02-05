package com.mi.car.jsse.easysec.tls;

public class AlertLevel {
    public static final short fatal = 2;
    public static final short warning = 1;

    public static String getName(short alertDescription) {
        switch (alertDescription) {
            case 1:
                return "warning";
            case 2:
                return "fatal";
            default:
                return "UNKNOWN";
        }
    }

    public static String getText(short alertDescription) {
        return getName(alertDescription) + "(" + ((int) alertDescription) + ")";
    }
}
