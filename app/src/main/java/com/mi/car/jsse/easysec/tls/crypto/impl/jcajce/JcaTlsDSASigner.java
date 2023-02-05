package com.mi.car.jsse.easysec.tls.crypto.impl.jcajce;

import com.mi.car.jsse.easysec.tls.HashAlgorithm;
import com.mi.car.jsse.easysec.tls.SignatureAndHashAlgorithm;
import com.mi.car.jsse.easysec.tls.crypto.TlsStreamSigner;
import java.io.IOException;
import java.security.PrivateKey;

public class JcaTlsDSASigner extends JcaTlsDSSSigner {
    public JcaTlsDSASigner(JcaTlsCrypto crypto, PrivateKey privateKey) {
        super(crypto, privateKey, (short) 2, "NoneWithDSA");
    }

    @Override // com.mi.car.jsse.easysec.tls.crypto.impl.jcajce.JcaTlsDSSSigner, com.mi.car.jsse.easysec.tls.crypto.TlsSigner
    public TlsStreamSigner getStreamSigner(SignatureAndHashAlgorithm algorithm) throws IOException {
        if (algorithm == null || this.algorithmType != algorithm.getSignature() || HashAlgorithm.getOutputSize(algorithm.getHash()) == 20) {
            return null;
        }
        return this.crypto.createStreamSigner(algorithm, this.privateKey, true);
    }
}
