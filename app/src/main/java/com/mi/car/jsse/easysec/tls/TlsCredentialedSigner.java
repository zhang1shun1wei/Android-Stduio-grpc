package com.mi.car.jsse.easysec.tls;

import com.mi.car.jsse.easysec.tls.crypto.TlsStreamSigner;
import java.io.IOException;

public interface TlsCredentialedSigner extends TlsCredentials {
    byte[] generateRawSignature(byte[] bArr) throws IOException;

    SignatureAndHashAlgorithm getSignatureAndHashAlgorithm();

    TlsStreamSigner getStreamSigner() throws IOException;
}
