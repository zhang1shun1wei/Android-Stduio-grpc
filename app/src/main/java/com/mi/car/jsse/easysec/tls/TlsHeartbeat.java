package com.mi.car.jsse.easysec.tls;

public interface TlsHeartbeat {
    byte[] generatePayload();

    int getIdleMillis();

    int getTimeoutMillis();
}
