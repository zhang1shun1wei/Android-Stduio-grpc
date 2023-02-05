package com.mi.car.jsse.easysec.tls.crypto.impl.jcajce;

import com.mi.car.jsse.easysec.tls.DigitallySigned;
import com.mi.car.jsse.easysec.tls.SignatureAndHashAlgorithm;
import com.mi.car.jsse.easysec.tls.crypto.TlsStreamVerifier;
import com.mi.car.jsse.easysec.tls.crypto.TlsVerifier;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.PublicKey;
import java.security.Signature;

public abstract class JcaTlsDSSVerifier implements TlsVerifier {
    protected final String algorithmName;
    protected final short algorithmType;
    protected final JcaTlsCrypto crypto;
    protected final PublicKey publicKey;

    protected JcaTlsDSSVerifier(JcaTlsCrypto crypto2, PublicKey publicKey2, short algorithmType2, String algorithmName2) {
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
    public TlsStreamVerifier getStreamVerifier(DigitallySigned signature) throws IOException {
        return null;
    }

    @Override // com.mi.car.jsse.easysec.tls.crypto.TlsVerifier
    public boolean verifyRawSignature(DigitallySigned signedParams, byte[] hash) {
        SignatureAndHashAlgorithm algorithm = signedParams.getAlgorithm();
        if (algorithm == null || algorithm.getSignature() == this.algorithmType) {
            try {
                Signature signer = this.crypto.getHelper().createSignature(this.algorithmName);
                signer.initVerify(this.publicKey);
                if (algorithm == null) {
                    signer.update(hash, 16, 20);
                } else {
                    signer.update(hash, 0, hash.length);
                }
                return signer.verify(signedParams.getSignature());
            } catch (GeneralSecurityException e) {
                throw Exceptions.illegalStateException("unable to process signature: " + e.getMessage(), e);
            }
        } else {
            throw new IllegalStateException("Invalid algorithm: " + algorithm);
        }
    }
}
