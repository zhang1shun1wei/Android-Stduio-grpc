package com.mi.car.jsse.easysec.tls;

public interface TlsSession {
    SessionParameters exportSessionParameters();

    byte[] getSessionID();

    void invalidate();

    boolean isResumable();
}
