package com.mi.car.jsse.easysec.tls.crypto;

import java.io.IOException;
import java.io.OutputStream;

public interface TlsStreamSigner {
    OutputStream getOutputStream() throws IOException;

    byte[] getSignature() throws IOException;
}
