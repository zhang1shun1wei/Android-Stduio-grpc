package com.mi.car.jsse.easysec.tls.crypto.impl.jcajce;

import com.mi.car.jsse.easysec.tls.DigitallySigned;
import com.mi.car.jsse.easysec.tls.SignatureAndHashAlgorithm;
import com.mi.car.jsse.easysec.tls.SignatureScheme;
import com.mi.car.jsse.easysec.tls.crypto.TlsStreamVerifier;
import com.mi.car.jsse.easysec.tls.crypto.TlsVerifier;
import java.security.GeneralSecurityException;
import java.security.PublicKey;
import java.security.Signature;

public class JcaTlsECDSA13Verifier implements TlsVerifier {
    private final JcaTlsCrypto crypto;
    private final PublicKey publicKey;
    private final int signatureScheme;

    public JcaTlsECDSA13Verifier(JcaTlsCrypto crypto2, PublicKey publicKey2, int signatureScheme2) {
        if (crypto2 == null) {
            throw new NullPointerException("crypto");
        } else if (publicKey2 == null) {
            throw new NullPointerException("publicKey");
        } else if (!SignatureScheme.isECDSA(signatureScheme2)) {
            throw new IllegalArgumentException("signatureScheme");
        } else {
            this.crypto = crypto2;
            this.publicKey = publicKey2;
            this.signatureScheme = signatureScheme2;
        }
    }

    @Override // com.mi.car.jsse.easysec.tls.crypto.TlsVerifier
    public TlsStreamVerifier getStreamVerifier(DigitallySigned signature) {
        return null;
    }

    @Override // com.mi.car.jsse.easysec.tls.crypto.TlsVerifier
    public boolean verifyRawSignature(DigitallySigned signature, byte[] hash) {
        SignatureAndHashAlgorithm algorithm = signature.getAlgorithm();
        if (algorithm == null || SignatureScheme.from(algorithm) != this.signatureScheme) {
            throw new IllegalStateException("Invalid algorithm: " + algorithm);
        }
        try {
            Signature signer = this.crypto.getHelper().createSignature("NoneWithECDSA");
            signer.initVerify(this.publicKey);
            signer.update(hash, 0, hash.length);
            return signer.verify(signature.getSignature());
        } catch (GeneralSecurityException e) {
            throw Exceptions.illegalStateException("unable to process signature: " + e.getMessage(), e);
        }
    }
}
