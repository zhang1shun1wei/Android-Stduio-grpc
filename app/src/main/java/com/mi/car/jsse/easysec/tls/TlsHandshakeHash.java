package com.mi.car.jsse.easysec.tls;

import com.mi.car.jsse.easysec.tls.crypto.TlsHash;
import java.io.IOException;
import java.io.OutputStream;

public interface TlsHandshakeHash extends TlsHash {
    void copyBufferTo(OutputStream outputStream) throws IOException;

    void forceBuffering();

    TlsHash forkPRFHash();

    byte[] getFinalHash(int i);

    void notifyPRFDetermined();

    void sealHashAlgorithms();

    void stopTracking();

    void trackHashAlgorithm(int i);
}
