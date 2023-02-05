package com.mi.car.jsse.easysec.tls.crypto.impl.jcajce;

import com.mi.car.jsse.easysec.tls.DigitallySigned;
import com.mi.car.jsse.easysec.tls.SignatureAndHashAlgorithm;
import com.mi.car.jsse.easysec.tls.crypto.TlsStreamVerifier;
import com.mi.car.jsse.easysec.tls.crypto.TlsVerifier;
import java.io.IOException;
import java.security.PublicKey;

public class JcaTlsEdDSAVerifier implements TlsVerifier {
    protected final String algorithmName;
    protected final short algorithmType;
    protected final JcaTlsCrypto crypto;
    protected final PublicKey publicKey;

    public JcaTlsEdDSAVerifier(JcaTlsCrypto crypto2, PublicKey publicKey2, short algorithmType2, String algorithmName2) {
        if (crypto2 == null) {
            throw new NullPointerException("crypto");
        } else if (publicKey2 == null) {
            throw new NullPointerException("publicKey");
        } else {
            this.crypto = crypto2;
            this.publicKey = publicKey2;
            this.algorithmType = algorithmType2;
            this.algorithmName = algorithmName2;
        }
    }

    @Override // com.mi.car.jsse.easysec.tls.crypto.TlsVerifier
    public boolean verifyRawSignature(DigitallySigned signature, byte[] hash) throws IOException {
        throw new UnsupportedOperationException();
    }

    @Override // com.mi.car.jsse.easysec.tls.crypto.TlsVerifier
    public TlsStreamVerifier getStreamVerifier(DigitallySigned signature) throws IOException {
        SignatureAndHashAlgorithm algorithm = signature.getAlgorithm();
        if (algorithm != null && algorithm.getSignature() == this.algorithmType && algorithm.getHash() == 8) {
            return this.crypto.createStreamVerifier(this.algorithmName, null, signature.getSignature(), this.publicKey);
        }
        throw new IllegalStateException("Invalid algorithm: " + algorithm);
    }
}
