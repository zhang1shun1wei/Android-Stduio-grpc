package com.mi.car.jsse.easysec.tls.crypto;

import java.io.IOException;

public interface TlsAgreement {
    TlsSecret calculateSecret() throws IOException;

    byte[] generateEphemeral() throws IOException;

    void receivePeerValue(byte[] bArr) throws IOException;
}
