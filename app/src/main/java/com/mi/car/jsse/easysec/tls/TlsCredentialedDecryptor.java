package com.mi.car.jsse.easysec.tls;

import com.mi.car.jsse.easysec.tls.crypto.TlsCryptoParameters;
import com.mi.car.jsse.easysec.tls.crypto.TlsSecret;
import java.io.IOException;

public interface TlsCredentialedDecryptor extends TlsCredentials {
    TlsSecret decrypt(TlsCryptoParameters tlsCryptoParameters, byte[] bArr) throws IOException;
}
