package com.mi.car.jsse.easysec.tls.crypto.impl.jcajce;

import com.mi.car.jsse.easysec.jcajce.io.OutputStreamFactory;
import com.mi.car.jsse.easysec.tls.TlsFatalAlert;
import com.mi.car.jsse.easysec.tls.crypto.TlsStreamSigner;
import java.io.IOException;
import java.io.OutputStream;
import java.security.Signature;
import java.security.SignatureException;

/* access modifiers changed from: package-private */
public class JcaTlsStreamSigner implements TlsStreamSigner {
    private final OutputStream output;
    private final Signature signer;

    JcaTlsStreamSigner(Signature signer2) {
        this.signer = signer2;
        this.output = OutputStreamFactory.createStream(signer2);
    }

    @Override // com.mi.car.jsse.easysec.tls.crypto.TlsStreamSigner
    public OutputStream getOutputStream() throws IOException {
        return this.output;
    }

    @Override // com.mi.car.jsse.easysec.tls.crypto.TlsStreamSigner
    public byte[] getSignature() throws IOException {
        try {
            return this.signer.sign();
        } catch (SignatureException e) {
            throw new TlsFatalAlert((short) 80, (Throwable) e);
        }
    }
}
