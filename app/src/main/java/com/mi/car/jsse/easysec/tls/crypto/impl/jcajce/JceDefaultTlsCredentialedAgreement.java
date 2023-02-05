package com.mi.car.jsse.easysec.tls.crypto.impl.jcajce;

import com.mi.car.jsse.easysec.tls.Certificate;
import com.mi.car.jsse.easysec.tls.TlsCredentialedAgreement;
import com.mi.car.jsse.easysec.tls.crypto.TlsCertificate;
import com.mi.car.jsse.easysec.tls.crypto.TlsCryptoException;
import com.mi.car.jsse.easysec.tls.crypto.TlsSecret;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import javax.crypto.interfaces.DHPrivateKey;

public class JceDefaultTlsCredentialedAgreement implements TlsCredentialedAgreement {
    private final String agreementAlgorithm;
    private final Certificate certificate;
    private final JcaTlsCrypto crypto;
    private final PrivateKey privateKey;

    public static String getAgreementAlgorithm(PrivateKey privateKey2) {
        if (privateKey2 instanceof DHPrivateKey) {
            return "DH";
        }
        if (ECUtil.isECPrivateKey(privateKey2)) {
            return "ECDH";
        }
        throw new IllegalArgumentException("'privateKey' type not supported: " + privateKey2.getClass().getName());
    }

    public JceDefaultTlsCredentialedAgreement(JcaTlsCrypto crypto2, Certificate certificate2, PrivateKey privateKey2) {
        if (crypto2 == null) {
            throw new IllegalArgumentException("'crypto' cannot be null");
        } else if (certificate2 == null) {
            throw new IllegalArgumentException("'certificate' cannot be null");
        } else if (certificate2.isEmpty()) {
            throw new IllegalArgumentException("'certificate' cannot be empty");
        } else if (privateKey2 == null) {
            throw new IllegalArgumentException("'privateKey' cannot be null");
        } else {
            this.crypto = crypto2;
            this.certificate = certificate2;
            this.privateKey = privateKey2;
            this.agreementAlgorithm = getAgreementAlgorithm(privateKey2);
        }
    }

    @Override // com.mi.car.jsse.easysec.tls.TlsCredentials
    public Certificate getCertificate() {
        return this.certificate;
    }

    @Override // com.mi.car.jsse.easysec.tls.TlsCredentialedAgreement
    public TlsSecret generateAgreement(TlsCertificate peerCertificate) throws IOException {
        try {
            return this.crypto.adoptLocalSecret(this.crypto.calculateKeyAgreement(this.agreementAlgorithm, this.privateKey, JcaTlsCertificate.convert(this.crypto, peerCertificate).getPublicKey(), "TlsPremasterSecret"));
        } catch (GeneralSecurityException e) {
            throw new TlsCryptoException("unable to perform agreement", e);
        }
    }
}
