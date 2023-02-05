package com.mi.car.jsse.easysec.tls.crypto.impl.bc;

import com.mi.car.jsse.easysec.crypto.Signer;
import com.mi.car.jsse.easysec.crypto.io.SignerOutputStream;
import com.mi.car.jsse.easysec.tls.crypto.TlsStreamVerifier;
import java.io.IOException;
import java.io.OutputStream;

class BcTlsStreamVerifier implements TlsStreamVerifier {
    private final SignerOutputStream output;
    private final byte[] signature;

    BcTlsStreamVerifier(Signer verifier, byte[] signature2) {
        this.output = new SignerOutputStream(verifier);
        this.signature = signature2;
    }

    @Override // com.mi.car.jsse.easysec.tls.crypto.TlsStreamVerifier
    public OutputStream getOutputStream() throws IOException {
        return this.output;
    }

    @Override // com.mi.car.jsse.easysec.tls.crypto.TlsStreamVerifier
    public boolean isVerified() throws IOException {
        return this.output.getSigner().verifySignature(this.signature);
    }
}
