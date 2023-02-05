package com.mi.car.jsse.easysec.tls;

import com.mi.car.jsse.easysec.tls.crypto.TlsCertificate;
import com.mi.car.jsse.easysec.tls.crypto.TlsSecret;
import java.io.IOException;

public interface TlsCredentialedAgreement extends TlsCredentials {
    TlsSecret generateAgreement(TlsCertificate tlsCertificate) throws IOException;
}
