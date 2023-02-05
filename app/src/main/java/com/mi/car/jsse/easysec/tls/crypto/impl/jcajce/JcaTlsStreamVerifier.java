package com.mi.car.jsse.easysec.tls.crypto.impl.jcajce;

import com.mi.car.jsse.easysec.jcajce.io.OutputStreamFactory;
import com.mi.car.jsse.easysec.tls.TlsFatalAlert;
import com.mi.car.jsse.easysec.tls.crypto.TlsStreamVerifier;
import java.io.IOException;
import java.io.OutputStream;
import java.security.Signature;
import java.security.SignatureException;

/* access modifiers changed from: package-private */
public class JcaTlsStreamVerifier implements TlsStreamVerifier {
    private final OutputStream output;
    private final byte[] signature;
    private final Signature verifier;

    JcaTlsStreamVerifier(Signature verifier2, byte[] signature2) {
        this.verifier = verifier2;
        this.output = OutputStreamFactory.createStream(verifier2);
        this.signature = signature2;
    }

    @Override // com.mi.car.jsse.easysec.tls.crypto.TlsStreamVerifier
    public OutputStream getOutputStream() throws IOException {
        return this.output;
    }

    @Override // com.mi.car.jsse.easysec.tls.crypto.TlsStreamVerifier
    public boolean isVerified() throws IOException {
        try {
            return this.verifier.verify(this.signature);
        } catch (SignatureException e) {
            throw new TlsFatalAlert((short) 80, (Throwable) e);
        }
    }
}
