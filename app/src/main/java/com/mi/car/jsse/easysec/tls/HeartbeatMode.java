package com.mi.car.jsse.easysec.tls;

public class HeartbeatMode {
    public static final short peer_allowed_to_send = 1;
    public static final short peer_not_allowed_to_send = 2;

    public static String getName(short heartbeatMode) {
        switch (heartbeatMode) {
            case 1:
                return "peer_allowed_to_send";
            case 2:
                return "peer_not_allowed_to_send";
            default:
                return "UNKNOWN";
        }
    }

    public static String getText(short heartbeatMode) {
        return getName(heartbeatMode) + "(" + ((int) heartbeatMode) + ")";
    }

    public static boolean isValid(short heartbeatMode) {
        return heartbeatMode >= 1 && heartbeatMode <= 2;
    }
}
