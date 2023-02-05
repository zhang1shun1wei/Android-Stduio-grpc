package com.mi.car.jsse.easysec.tls.crypto;

import com.mi.car.jsse.easysec.tls.DigitallySigned;
import java.io.IOException;

public interface TlsVerifier {
    TlsStreamVerifier getStreamVerifier(DigitallySigned digitallySigned) throws IOException;

    boolean verifyRawSignature(DigitallySigned digitallySigned, byte[] bArr) throws IOException;
}
