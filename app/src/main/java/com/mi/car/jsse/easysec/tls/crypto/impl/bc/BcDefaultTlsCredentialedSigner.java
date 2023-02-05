package com.mi.car.jsse.easysec.tls.crypto.impl.bc;

import com.mi.car.jsse.easysec.crypto.params.AsymmetricKeyParameter;
import com.mi.car.jsse.easysec.crypto.params.DSAPrivateKeyParameters;
import com.mi.car.jsse.easysec.crypto.params.ECPrivateKeyParameters;
import com.mi.car.jsse.easysec.crypto.params.Ed25519PrivateKeyParameters;
import com.mi.car.jsse.easysec.crypto.params.Ed448PrivateKeyParameters;
import com.mi.car.jsse.easysec.crypto.params.RSAKeyParameters;
import com.mi.car.jsse.easysec.tls.Certificate;
import com.mi.car.jsse.easysec.tls.DefaultTlsCredentialedSigner;
import com.mi.car.jsse.easysec.tls.SignatureAndHashAlgorithm;
import com.mi.car.jsse.easysec.tls.SignatureScheme;
import com.mi.car.jsse.easysec.tls.crypto.TlsCryptoParameters;
import com.mi.car.jsse.easysec.tls.crypto.TlsSigner;
import java.io.IOException;

public class BcDefaultTlsCredentialedSigner extends DefaultTlsCredentialedSigner {
    private static BcTlsCertificate getEndEntity(BcTlsCrypto crypto, Certificate certificate) throws IOException {
        if (certificate != null && !certificate.isEmpty()) {
            return BcTlsCertificate.convert(crypto, certificate.getCertificateAt(0));
        }
        throw new IllegalArgumentException("No certificate");
    }

    private static TlsSigner makeSigner(BcTlsCrypto crypto, AsymmetricKeyParameter privateKey, Certificate certificate, SignatureAndHashAlgorithm signatureAndHashAlgorithm) {
        if (privateKey instanceof RSAKeyParameters) {
            RSAKeyParameters privKeyRSA = (RSAKeyParameters) privateKey;
            if (signatureAndHashAlgorithm != null) {
                int signatureScheme = SignatureScheme.from(signatureAndHashAlgorithm);
                if (SignatureScheme.isRSAPSS(signatureScheme)) {
                    return new BcTlsRSAPSSSigner(crypto, privKeyRSA, signatureScheme);
                }
            }
            try {
                return new BcTlsRSASigner(crypto, privKeyRSA, getEndEntity(crypto, certificate).getPubKeyRSA());
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
        } else if (privateKey instanceof DSAPrivateKeyParameters) {
            return new BcTlsDSASigner(crypto, (DSAPrivateKeyParameters) privateKey);
        } else {
            if (privateKey instanceof ECPrivateKeyParameters) {
                ECPrivateKeyParameters privKeyEC = (ECPrivateKeyParameters) privateKey;
                if (signatureAndHashAlgorithm != null) {
                    int signatureScheme2 = SignatureScheme.from(signatureAndHashAlgorithm);
                    if (SignatureScheme.isECDSA(signatureScheme2)) {
                        return new BcTlsECDSA13Signer(crypto, privKeyEC, signatureScheme2);
                    }
                }
                return new BcTlsECDSASigner(crypto, privKeyEC);
            } else if (privateKey instanceof Ed25519PrivateKeyParameters) {
                return new BcTlsEd25519Signer(crypto, (Ed25519PrivateKeyParameters) privateKey);
            } else {
                if (privateKey instanceof Ed448PrivateKeyParameters) {
                    return new BcTlsEd448Signer(crypto, (Ed448PrivateKeyParameters) privateKey);
                }
                throw new IllegalArgumentException("'privateKey' type not supported: " + privateKey.getClass().getName());
            }
        }
    }

    public BcDefaultTlsCredentialedSigner(TlsCryptoParameters cryptoParams, BcTlsCrypto crypto, AsymmetricKeyParameter privateKey, Certificate certificate, SignatureAndHashAlgorithm signatureAndHashAlgorithm) {
        super(cryptoParams, makeSigner(crypto, privateKey, certificate, signatureAndHashAlgorithm), certificate, signatureAndHashAlgorithm);
    }
}
