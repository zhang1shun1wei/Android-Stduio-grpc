package com.mi.car.jsse.easysec.tls.crypto.impl.jcajce;

import com.mi.car.jsse.easysec.tls.DigitallySigned;
import com.mi.car.jsse.easysec.tls.SignatureAndHashAlgorithm;
import com.mi.car.jsse.easysec.tls.SignatureScheme;
import com.mi.car.jsse.easysec.tls.crypto.TlsStreamVerifier;
import com.mi.car.jsse.easysec.tls.crypto.TlsVerifier;
import java.io.IOException;
import java.security.PublicKey;

public class JcaTlsRSAPSSVerifier implements TlsVerifier {
    private final JcaTlsCrypto crypto;
    private final PublicKey publicKey;
    private final int signatureScheme;

    public JcaTlsRSAPSSVerifier(JcaTlsCrypto crypto2, PublicKey publicKey2, int signatureScheme2) {
        if (crypto2 == null) {
            throw new NullPointerException("crypto");
        } else if (publicKey2 == null) {
            throw new NullPointerException("publicKey");
        } else if (!SignatureScheme.isRSAPSS(signatureScheme2)) {
            throw new IllegalArgumentException("signatureScheme");
        } else {
            this.crypto = crypto2;
            this.publicKey = publicKey2;
            this.signatureScheme = signatureScheme2;
        }
    }

    @Override // com.mi.car.jsse.easysec.tls.crypto.TlsVerifier
    public boolean verifyRawSignature(DigitallySigned signature, byte[] hash) throws IOException {
        throw new UnsupportedOperationException();
    }

    @Override // com.mi.car.jsse.easysec.tls.crypto.TlsVerifier
    public TlsStreamVerifier getStreamVerifier(DigitallySigned signature) throws IOException {
        SignatureAndHashAlgorithm algorithm = signature.getAlgorithm();
        if (algorithm == null || SignatureScheme.from(algorithm) != this.signatureScheme) {
            throw new IllegalStateException("Invalid algorithm: " + algorithm);
        }
        int cryptoHashAlgorithm = SignatureScheme.getCryptoHashAlgorithm(this.signatureScheme);
        String digestName = this.crypto.getDigestName(cryptoHashAlgorithm);
        return this.crypto.createStreamVerifier(RSAUtil.getDigestSigAlgName(digestName) + "WITHRSAANDMGF1", RSAUtil.getPSSParameterSpec(cryptoHashAlgorithm, digestName, this.crypto.getHelper()), signature.getSignature(), this.publicKey);
    }
}
