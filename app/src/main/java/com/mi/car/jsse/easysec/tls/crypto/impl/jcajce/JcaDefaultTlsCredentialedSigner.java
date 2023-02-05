package com.mi.car.jsse.easysec.tls.crypto.impl.jcajce;

import com.mi.car.jsse.easysec.tls.Certificate;
import com.mi.car.jsse.easysec.tls.DefaultTlsCredentialedSigner;
import com.mi.car.jsse.easysec.tls.SignatureAndHashAlgorithm;
import com.mi.car.jsse.easysec.tls.SignatureScheme;
import com.mi.car.jsse.easysec.tls.crypto.TlsCryptoParameters;
import com.mi.car.jsse.easysec.tls.crypto.TlsSigner;
import java.io.IOException;
import java.security.PrivateKey;
import java.security.interfaces.DSAPrivateKey;
import java.security.interfaces.RSAPrivateKey;

public class JcaDefaultTlsCredentialedSigner extends DefaultTlsCredentialedSigner {
    private static JcaTlsCertificate getEndEntity(JcaTlsCrypto crypto, Certificate certificate) throws IOException {
        if (certificate != null && !certificate.isEmpty()) {
            return JcaTlsCertificate.convert(crypto, certificate.getCertificateAt(0));
        }
        throw new IllegalArgumentException("No certificate");
    }

    private static TlsSigner makeSigner(JcaTlsCrypto crypto, PrivateKey privateKey, Certificate certificate, SignatureAndHashAlgorithm signatureAndHashAlgorithm) {
        String algorithm = privateKey.getAlgorithm();
        if ((privateKey instanceof RSAPrivateKey) || "RSA".equalsIgnoreCase(algorithm) || "RSASSA-PSS".equalsIgnoreCase(algorithm)) {
            if (signatureAndHashAlgorithm != null) {
                int signatureScheme = SignatureScheme.from(signatureAndHashAlgorithm);
                if (SignatureScheme.isRSAPSS(signatureScheme)) {
                    return new JcaTlsRSAPSSSigner(crypto, privateKey, signatureScheme);
                }
            }
            try {
                return new JcaTlsRSASigner(crypto, privateKey, getEndEntity(crypto, certificate).getPubKeyRSA());
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
        } else if ((privateKey instanceof DSAPrivateKey) || "DSA".equalsIgnoreCase(algorithm)) {
            return new JcaTlsDSASigner(crypto, privateKey);
        } else {
            if (ECUtil.isECPrivateKey(privateKey)) {
                if (signatureAndHashAlgorithm != null) {
                    int signatureScheme2 = SignatureScheme.from(signatureAndHashAlgorithm);
                    if (SignatureScheme.isECDSA(signatureScheme2)) {
                        return new JcaTlsECDSA13Signer(crypto, privateKey, signatureScheme2);
                    }
                }
                return new JcaTlsECDSASigner(crypto, privateKey);
            } else if ("Ed25519".equalsIgnoreCase(algorithm)) {
                return new JcaTlsEd25519Signer(crypto, privateKey);
            } else {
                if ("Ed448".equalsIgnoreCase(algorithm)) {
                    return new JcaTlsEd448Signer(crypto, privateKey);
                }
                throw new IllegalArgumentException("'privateKey' type not supported: " + privateKey.getClass().getName());
            }
        }
    }

    public JcaDefaultTlsCredentialedSigner(TlsCryptoParameters cryptoParams, JcaTlsCrypto crypto, PrivateKey privateKey, Certificate certificate, SignatureAndHashAlgorithm signatureAndHashAlgorithm) {
        super(cryptoParams, makeSigner(crypto, privateKey, certificate, signatureAndHashAlgorithm), certificate, signatureAndHashAlgorithm);
    }
}
