package com.mi.car.jsse.easysec.tls.crypto;

import com.mi.car.jsse.easysec.tls.SignatureAndHashAlgorithm;
import java.io.IOException;

public interface TlsSigner {
    byte[] generateRawSignature(SignatureAndHashAlgorithm signatureAndHashAlgorithm, byte[] bArr) throws IOException;

    TlsStreamSigner getStreamSigner(SignatureAndHashAlgorithm signatureAndHashAlgorithm) throws IOException;
}
