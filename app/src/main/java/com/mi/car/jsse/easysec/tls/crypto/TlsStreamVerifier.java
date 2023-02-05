package com.mi.car.jsse.easysec.tls.crypto;

import java.io.IOException;
import java.io.OutputStream;

public interface TlsStreamVerifier {
    OutputStream getOutputStream() throws IOException;

    boolean isVerified() throws IOException;
}
