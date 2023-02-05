package com.mi.car.jsse.easysec.tls.crypto.impl.bc;

import com.mi.car.jsse.easysec.crypto.CryptoException;
import com.mi.car.jsse.easysec.crypto.Signer;
import com.mi.car.jsse.easysec.crypto.io.SignerOutputStream;
import com.mi.car.jsse.easysec.tls.TlsFatalAlert;
import com.mi.car.jsse.easysec.tls.crypto.TlsStreamSigner;
import java.io.IOException;
import java.io.OutputStream;

class BcTlsStreamSigner implements TlsStreamSigner {
    private final SignerOutputStream output;

    BcTlsStreamSigner(Signer signer) {
        this.output = new SignerOutputStream(signer);
    }

    @Override // com.mi.car.jsse.easysec.tls.crypto.TlsStreamSigner
    public OutputStream getOutputStream() throws IOException {
        return this.output;
    }

    @Override // com.mi.car.jsse.easysec.tls.crypto.TlsStreamSigner
    public byte[] getSignature() throws IOException {
        try {
            return this.output.getSigner().generateSignature();
        } catch (CryptoException e) {
            throw new TlsFatalAlert((short) 80, (Throwable) e);
        }
    }
}
