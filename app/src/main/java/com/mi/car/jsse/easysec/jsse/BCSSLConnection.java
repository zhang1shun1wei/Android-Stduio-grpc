package com.mi.car.jsse.easysec.jsse;

public interface BCSSLConnection {
    String getApplicationProtocol();

    byte[] getChannelBinding(String str);

    BCExtendedSSLSession getSession();
}
