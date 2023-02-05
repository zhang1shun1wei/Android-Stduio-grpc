package com.mi.car.jsse.easysec.jsse;

import java.util.Collections;
import java.util.List;
import javax.net.ssl.SSLSession;

public abstract class BCExtendedSSLSession implements SSLSession {
    public abstract String[] getLocalSupportedSignatureAlgorithms();

    public abstract String[] getPeerSupportedSignatureAlgorithms();

    public abstract boolean isFipsMode();

    public String[] getLocalSupportedSignatureAlgorithmsBC() {
        return getLocalSupportedSignatureAlgorithms();
    }

    public String[] getPeerSupportedSignatureAlgorithmsBC() {
        return getPeerSupportedSignatureAlgorithms();
    }

    public List<BCSNIServerName> getRequestedServerNames() {
        throw new UnsupportedOperationException();
    }

    public List<byte[]> getStatusResponses() {
        return Collections.emptyList();
    }
}
