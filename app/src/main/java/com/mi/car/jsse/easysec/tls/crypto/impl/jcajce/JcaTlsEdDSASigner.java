package com.mi.car.jsse.easysec.tls.crypto.impl.jcajce;

import com.mi.car.jsse.easysec.tls.SignatureAndHashAlgorithm;
import com.mi.car.jsse.easysec.tls.crypto.TlsSigner;
import com.mi.car.jsse.easysec.tls.crypto.TlsStreamSigner;
import java.io.IOException;
import java.security.PrivateKey;

public abstract class JcaTlsEdDSASigner implements TlsSigner {
    protected final String algorithmName;
    protected final short algorithmType;
    protected final JcaTlsCrypto crypto;
    protected final PrivateKey privateKey;

    public JcaTlsEdDSASigner(JcaTlsCrypto crypto2, PrivateKey privateKey2, short algorithmType2, String algorithmName2) {
        if (crypto2 == null) {
            throw new NullPointerException("crypto");
        } else if (privateKey2 == null) {
            throw new NullPointerException("privateKey");
        } else {
            this.crypto = crypto2;
            this.privateKey = privateKey2;
            this.algorithmType = algorithmType2;
            this.algorithmName = algorithmName2;
        }
    }

    @Override // com.mi.car.jsse.easysec.tls.crypto.TlsSigner
    public byte[] generateRawSignature(SignatureAndHashAlgorithm algorithm, byte[] hash) throws IOException {
        throw new UnsupportedOperationException();
    }

    @Override // com.mi.car.jsse.easysec.tls.crypto.TlsSigner
    public TlsStreamSigner getStreamSigner(SignatureAndHashAlgorithm algorithm) throws IOException {
        if (algorithm != null && algorithm.getSignature() == this.algorithmType && algorithm.getHash() == 8) {
            return this.crypto.createStreamSigner(this.algorithmName, null, this.privateKey, false);
        }
        throw new IllegalStateException("Invalid algorithm: " + algorithm);
    }
}
