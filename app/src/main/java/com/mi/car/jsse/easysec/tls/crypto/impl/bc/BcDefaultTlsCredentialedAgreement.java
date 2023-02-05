package com.mi.car.jsse.easysec.tls.crypto.impl.bc;

import com.mi.car.jsse.easysec.crypto.params.AsymmetricKeyParameter;
import com.mi.car.jsse.easysec.crypto.params.DHPrivateKeyParameters;
import com.mi.car.jsse.easysec.crypto.params.ECPrivateKeyParameters;
import com.mi.car.jsse.easysec.tls.Certificate;
import com.mi.car.jsse.easysec.tls.TlsCredentialedAgreement;
import com.mi.car.jsse.easysec.tls.crypto.TlsCertificate;
import com.mi.car.jsse.easysec.tls.crypto.TlsSecret;
import java.io.IOException;

public class BcDefaultTlsCredentialedAgreement implements TlsCredentialedAgreement {
    protected TlsCredentialedAgreement agreementCredentials;

    public BcDefaultTlsCredentialedAgreement(BcTlsCrypto crypto, Certificate certificate, AsymmetricKeyParameter privateKey) {
        if (crypto == null) {
            throw new IllegalArgumentException("'crypto' cannot be null");
        } else if (certificate == null) {
            throw new IllegalArgumentException("'certificate' cannot be null");
        } else if (certificate.isEmpty()) {
            throw new IllegalArgumentException("'certificate' cannot be empty");
        } else if (privateKey == null) {
            throw new IllegalArgumentException("'privateKey' cannot be null");
        } else if (!privateKey.isPrivate()) {
            throw new IllegalArgumentException("'privateKey' must be private");
        } else if (privateKey instanceof DHPrivateKeyParameters) {
            this.agreementCredentials = new DHCredentialedAgreement(crypto, certificate, (DHPrivateKeyParameters) privateKey);
        } else if (privateKey instanceof ECPrivateKeyParameters) {
            this.agreementCredentials = new ECCredentialedAgreement(crypto, certificate, (ECPrivateKeyParameters) privateKey);
        } else {
            throw new IllegalArgumentException("'privateKey' type not supported: " + privateKey.getClass().getName());
        }
    }

    @Override // com.mi.car.jsse.easysec.tls.TlsCredentials
    public Certificate getCertificate() {
        return this.agreementCredentials.getCertificate();
    }

    @Override // com.mi.car.jsse.easysec.tls.TlsCredentialedAgreement
    public TlsSecret generateAgreement(TlsCertificate peerCertificate) throws IOException {
        return this.agreementCredentials.generateAgreement(peerCertificate);
    }

    private class DHCredentialedAgreement implements TlsCredentialedAgreement {
        final Certificate certificate;
        final BcTlsCrypto crypto;
        final DHPrivateKeyParameters privateKey;

        DHCredentialedAgreement(BcTlsCrypto crypto2, Certificate certificate2, DHPrivateKeyParameters privateKey2) {
            this.crypto = crypto2;
            this.certificate = certificate2;
            this.privateKey = privateKey2;
        }

        @Override // com.mi.car.jsse.easysec.tls.TlsCredentialedAgreement
        public TlsSecret generateAgreement(TlsCertificate peerCertificate) throws IOException {
            return BcTlsDHDomain.calculateDHAgreement(this.crypto, this.privateKey, BcTlsCertificate.convert(this.crypto, peerCertificate).getPubKeyDH(), false);
        }

        @Override // com.mi.car.jsse.easysec.tls.TlsCredentials
        public Certificate getCertificate() {
            return this.certificate;
        }
    }

    private class ECCredentialedAgreement implements TlsCredentialedAgreement {
        final Certificate certificate;
        final BcTlsCrypto crypto;
        final ECPrivateKeyParameters privateKey;

        ECCredentialedAgreement(BcTlsCrypto crypto2, Certificate certificate2, ECPrivateKeyParameters privateKey2) {
            this.crypto = crypto2;
            this.certificate = certificate2;
            this.privateKey = privateKey2;
        }

        @Override // com.mi.car.jsse.easysec.tls.TlsCredentialedAgreement
        public TlsSecret generateAgreement(TlsCertificate peerCertificate) throws IOException {
            return BcTlsECDomain.calculateECDHAgreement(this.crypto, this.privateKey, BcTlsCertificate.convert(this.crypto, peerCertificate).getPubKeyEC());
        }

        @Override // com.mi.car.jsse.easysec.tls.TlsCredentials
        public Certificate getCertificate() {
            return this.certificate;
        }
    }
}
