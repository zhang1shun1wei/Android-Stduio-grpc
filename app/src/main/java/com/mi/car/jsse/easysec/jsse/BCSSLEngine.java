package com.mi.car.jsse.easysec.jsse;

import javax.net.ssl.SSLEngine;

public interface BCSSLEngine {
    String getApplicationProtocol();

    BCApplicationProtocolSelector<SSLEngine> getBCHandshakeApplicationProtocolSelector();

    BCExtendedSSLSession getBCHandshakeSession();

    BCExtendedSSLSession getBCSession();

    BCSSLConnection getConnection();

    String getHandshakeApplicationProtocol();

    BCSSLParameters getParameters();

    void setBCHandshakeApplicationProtocolSelector(BCApplicationProtocolSelector<SSLEngine> bCApplicationProtocolSelector);

    void setBCSessionToResume(BCExtendedSSLSession bCExtendedSSLSession);

    void setParameters(BCSSLParameters bCSSLParameters);
}
