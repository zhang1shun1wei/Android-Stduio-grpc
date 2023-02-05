package com.mi.car.jsse.easysec.tls.crypto.impl.jcajce;

import com.mi.car.jsse.easysec.tls.DigitallySigned;
import com.mi.car.jsse.easysec.tls.HashAlgorithm;
import com.mi.car.jsse.easysec.tls.SignatureAndHashAlgorithm;
import com.mi.car.jsse.easysec.tls.crypto.TlsStreamVerifier;
import java.io.IOException;
import java.security.PublicKey;

public class JcaTlsDSAVerifier extends JcaTlsDSSVerifier {
    public JcaTlsDSAVerifier(JcaTlsCrypto crypto, PublicKey publicKey) {
        super(crypto, publicKey, (short) 2, "NoneWithDSA");
    }

    @Override // com.mi.car.jsse.easysec.tls.crypto.TlsVerifier, com.mi.car.jsse.easysec.tls.crypto.impl.jcajce.JcaTlsDSSVerifier
    public TlsStreamVerifier getStreamVerifier(DigitallySigned signature) throws IOException {
        SignatureAndHashAlgorithm algorithm = signature.getAlgorithm();
        if (algorithm == null || this.algorithmType != algorithm.getSignature() || HashAlgorithm.getOutputSize(algorithm.getHash()) == 20) {
            return null;
        }
        return this.crypto.createStreamVerifier(signature, this.publicKey);
    }
}
