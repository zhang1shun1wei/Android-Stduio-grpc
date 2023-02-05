package com.mi.car.jsse.easysec.tls.crypto.impl.jcajce;

import com.mi.car.jsse.easysec.jcajce.io.OutputStreamFactory;
import com.mi.car.jsse.easysec.tls.TlsFatalAlert;
import com.mi.car.jsse.easysec.tls.crypto.TlsStreamSigner;
import com.mi.car.jsse.easysec.util.io.TeeOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.security.Signature;
import java.security.SignatureException;

/* access modifiers changed from: package-private */
public class JcaVerifyingStreamSigner implements TlsStreamSigner {
    private final OutputStream output;
    private final Signature signer;
    private final Signature verifier;

    JcaVerifyingStreamSigner(Signature signer2, Signature verifier2) {
        OutputStream outputSigner = OutputStreamFactory.createStream(signer2);
        OutputStream outputVerifier = OutputStreamFactory.createStream(verifier2);
        this.signer = signer2;
        this.verifier = verifier2;
        this.output = new TeeOutputStream(outputSigner, outputVerifier);
    }

    @Override // com.mi.car.jsse.easysec.tls.crypto.TlsStreamSigner
    public OutputStream getOutputStream() throws IOException {
        return this.output;
    }

    @Override // com.mi.car.jsse.easysec.tls.crypto.TlsStreamSigner
    public byte[] getSignature() throws IOException {
        try {
            byte[] signature = this.signer.sign();
            if (this.verifier.verify(signature)) {
                return signature;
            }
            throw new TlsFatalAlert((short) 80);
        } catch (SignatureException e) {
            throw new TlsFatalAlert((short) 80, (Throwable) e);
        }
    }
}
