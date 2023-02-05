package com.mi.car.jsse.easysec.tls;

public class HeartbeatMessageType {
    public static final short heartbeat_request = 1;
    public static final short heartbeat_response = 2;

    public static String getName(short heartbeatMessageType) {
        switch (heartbeatMessageType) {
            case 1:
                return "heartbeat_request";
            case 2:
                return "heartbeat_response";
            default:
                return "UNKNOWN";
        }
    }

    public static String getText(short heartbeatMessageType) {
        return getName(heartbeatMessageType) + "(" + ((int) heartbeatMessageType) + ")";
    }

    public static boolean isValid(short heartbeatMessageType) {
        return heartbeatMessageType >= 1 && heartbeatMessageType <= 2;
    }
}
