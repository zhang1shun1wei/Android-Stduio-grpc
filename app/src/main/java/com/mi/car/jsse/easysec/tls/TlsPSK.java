package com.mi.car.jsse.easysec.tls;

import com.mi.car.jsse.easysec.tls.crypto.TlsSecret;

public interface TlsPSK {
    byte[] getIdentity();

    TlsSecret getKey();

    int getPRFAlgorithm();
}
