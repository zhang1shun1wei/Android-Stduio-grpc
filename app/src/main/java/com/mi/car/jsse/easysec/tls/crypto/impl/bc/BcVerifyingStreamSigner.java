package com.mi.car.jsse.easysec.tls.crypto.impl.bc;

import com.mi.car.jsse.easysec.crypto.CryptoException;
import com.mi.car.jsse.easysec.crypto.Signer;
import com.mi.car.jsse.easysec.crypto.io.SignerOutputStream;
import com.mi.car.jsse.easysec.tls.TlsFatalAlert;
import com.mi.car.jsse.easysec.tls.crypto.TlsStreamSigner;
import com.mi.car.jsse.easysec.util.io.TeeOutputStream;
import java.io.IOException;
import java.io.OutputStream;

class BcVerifyingStreamSigner implements TlsStreamSigner {
    private final TeeOutputStream output;
    private final Signer signer;
    private final Signer verifier;

    BcVerifyingStreamSigner(Signer signer2, Signer verifier2) {
        OutputStream outputSigner = new SignerOutputStream(signer2);
        OutputStream outputVerifier = new SignerOutputStream(verifier2);
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
            byte[] signature = this.signer.generateSignature();
            if (this.verifier.verifySignature(signature)) {
                return signature;
            }
            throw new TlsFatalAlert((short) 80);
        } catch (CryptoException e) {
            throw new TlsFatalAlert((short) 80, (Throwable) e);
        }
    }
}
