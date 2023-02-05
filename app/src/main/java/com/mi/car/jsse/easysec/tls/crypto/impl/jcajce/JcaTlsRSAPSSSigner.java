package com.mi.car.jsse.easysec.tls.crypto.impl.jcajce;

import com.mi.car.jsse.easysec.tls.SignatureAndHashAlgorithm;
import com.mi.car.jsse.easysec.tls.SignatureScheme;
import com.mi.car.jsse.easysec.tls.crypto.TlsSigner;
import com.mi.car.jsse.easysec.tls.crypto.TlsStreamSigner;
import java.io.IOException;
import java.security.PrivateKey;

public class JcaTlsRSAPSSSigner implements TlsSigner {
    private final JcaTlsCrypto crypto;
    private final PrivateKey privateKey;
    private final int signatureScheme;

    public JcaTlsRSAPSSSigner(JcaTlsCrypto crypto2, PrivateKey privateKey2, int signatureScheme2) {
        if (crypto2 == null) {
            throw new NullPointerException("crypto");
        } else if (privateKey2 == null) {
            throw new NullPointerException("privateKey");
        } else if (!SignatureScheme.isRSAPSS(signatureScheme2)) {
            throw new IllegalArgumentException("signatureScheme");
        } else {
            this.crypto = crypto2;
            this.privateKey = privateKey2;
            this.signatureScheme = signatureScheme2;
        }
    }

    @Override // com.mi.car.jsse.easysec.tls.crypto.TlsSigner
    public byte[] generateRawSignature(SignatureAndHashAlgorithm algorithm, byte[] hash) throws IOException {
        throw new UnsupportedOperationException();
    }

    @Override // com.mi.car.jsse.easysec.tls.crypto.TlsSigner
    public TlsStreamSigner getStreamSigner(SignatureAndHashAlgorithm algorithm) throws IOException {
        if (algorithm == null || SignatureScheme.from(algorithm) != this.signatureScheme) {
            throw new IllegalStateException("Invalid algorithm: " + algorithm);
        }
        int cryptoHashAlgorithm = SignatureScheme.getCryptoHashAlgorithm(this.signatureScheme);
        String digestName = this.crypto.getDigestName(cryptoHashAlgorithm);
        return this.crypto.createStreamSigner(RSAUtil.getDigestSigAlgName(digestName) + "WITHRSAANDMGF1", RSAUtil.getPSSParameterSpec(cryptoHashAlgorithm, digestName, this.crypto.getHelper()), this.privateKey, true);
    }
}
