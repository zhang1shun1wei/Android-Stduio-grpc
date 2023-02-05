package com.mi.car.jsse.easysec.tls;

import com.mi.car.jsse.easysec.tls.crypto.TlsCertificate;
import com.mi.car.jsse.easysec.tls.crypto.TlsSecret;
import java.io.IOException;
import java.io.OutputStream;

public abstract class TlsRSAUtils {
    public static TlsSecret generateEncryptedPreMasterSecret(TlsContext context, TlsCertificate certificate, OutputStream output) throws IOException {
        return TlsUtils.generateEncryptedPreMasterSecret(context, certificate.createEncryptor(3), output);
    }
}
