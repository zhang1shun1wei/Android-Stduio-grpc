package com.mi.car.jsse.easysec.tls.crypto.impl.jcajce;

import com.mi.car.jsse.easysec.tls.SignatureAndHashAlgorithm;
import com.mi.car.jsse.easysec.tls.TlsFatalAlert;
import com.mi.car.jsse.easysec.tls.crypto.TlsSigner;
import com.mi.car.jsse.easysec.tls.crypto.TlsStreamSigner;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.Signature;

public abstract class JcaTlsDSSSigner implements TlsSigner {
    protected final String algorithmName;
    protected final short algorithmType;
    protected final JcaTlsCrypto crypto;
    protected final PrivateKey privateKey;

    protected JcaTlsDSSSigner(JcaTlsCrypto crypto2, PrivateKey privateKey2, short algorithmType2, String algorithmName2) {
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
        if (algorithm == null || algorithm.getSignature() == this.algorithmType) {
            try {
                Signature signer = this.crypto.getHelper().createSignature(this.algorithmName);
                signer.initSign(this.privateKey, this.crypto.getSecureRandom());
                if (algorithm == null) {
                    signer.update(hash, 16, 20);
                } else {
                    signer.update(hash, 0, hash.length);
                }
                return signer.sign();
            } catch (GeneralSecurityException e) {
                throw new TlsFatalAlert((short) 80, (Throwable) e);
            }
        } else {
            throw new IllegalStateException("Invalid algorithm: " + algorithm);
        }
    }

    @Override // com.mi.car.jsse.easysec.tls.crypto.TlsSigner
    public TlsStreamSigner getStreamSigner(SignatureAndHashAlgorithm algorithm) throws IOException {
        return null;
    }
}
