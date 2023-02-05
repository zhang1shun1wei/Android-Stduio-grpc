package com.mi.car.jsse.easysec.tls;

import com.mi.car.jsse.easysec.tls.crypto.TlsCryptoParameters;
import com.mi.car.jsse.easysec.tls.crypto.TlsSigner;
import com.mi.car.jsse.easysec.tls.crypto.TlsStreamSigner;
import com.mi.car.jsse.easysec.tls.crypto.impl.TlsImplUtils;
import java.io.IOException;

public class DefaultTlsCredentialedSigner implements TlsCredentialedSigner {
    protected Certificate certificate;
    protected TlsCryptoParameters cryptoParams;
    protected SignatureAndHashAlgorithm signatureAndHashAlgorithm;
    protected TlsSigner signer;

    public DefaultTlsCredentialedSigner(TlsCryptoParameters cryptoParams2, TlsSigner signer2, Certificate certificate2, SignatureAndHashAlgorithm signatureAndHashAlgorithm2) {
        if (certificate2 == null) {
            throw new IllegalArgumentException("'certificate' cannot be null");
        } else if (certificate2.isEmpty()) {
            throw new IllegalArgumentException("'certificate' cannot be empty");
        } else if (signer2 == null) {
            throw new IllegalArgumentException("'signer' cannot be null");
        } else {
            this.signer = signer2;
            this.cryptoParams = cryptoParams2;
            this.certificate = certificate2;
            this.signatureAndHashAlgorithm = signatureAndHashAlgorithm2;
        }
    }

    @Override // com.mi.car.jsse.easysec.tls.TlsCredentials
    public Certificate getCertificate() {
        return this.certificate;
    }

    @Override // com.mi.car.jsse.easysec.tls.TlsCredentialedSigner
    public byte[] generateRawSignature(byte[] hash) throws IOException {
        return this.signer.generateRawSignature(getEffectiveAlgorithm(), hash);
    }

    @Override // com.mi.car.jsse.easysec.tls.TlsCredentialedSigner
    public SignatureAndHashAlgorithm getSignatureAndHashAlgorithm() {
        return this.signatureAndHashAlgorithm;
    }

    @Override // com.mi.car.jsse.easysec.tls.TlsCredentialedSigner
    public TlsStreamSigner getStreamSigner() throws IOException {
        return this.signer.getStreamSigner(getEffectiveAlgorithm());
    }

    /* access modifiers changed from: protected */
    public SignatureAndHashAlgorithm getEffectiveAlgorithm() {
        SignatureAndHashAlgorithm algorithm = null;
        if (!TlsImplUtils.isTLSv12(this.cryptoParams) || (algorithm = getSignatureAndHashAlgorithm()) != null) {
            return algorithm;
        }
        throw new IllegalStateException("'signatureAndHashAlgorithm' cannot be null for (D)TLS 1.2+");
    }
}
