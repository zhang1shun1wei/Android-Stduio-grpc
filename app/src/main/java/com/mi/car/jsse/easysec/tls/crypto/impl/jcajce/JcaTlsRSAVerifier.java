package com.mi.car.jsse.easysec.tls.crypto.impl.jcajce;

import com.mi.car.jsse.easysec.asn1.DERNull;
import com.mi.car.jsse.easysec.asn1.x509.AlgorithmIdentifier;
import com.mi.car.jsse.easysec.asn1.x509.DigestInfo;
import com.mi.car.jsse.easysec.tls.DigitallySigned;
import com.mi.car.jsse.easysec.tls.SignatureAndHashAlgorithm;
import com.mi.car.jsse.easysec.tls.TlsUtils;
import com.mi.car.jsse.easysec.tls.crypto.TlsStreamVerifier;
import com.mi.car.jsse.easysec.tls.crypto.TlsVerifier;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.PublicKey;
import java.security.Signature;

public class JcaTlsRSAVerifier implements TlsVerifier {
    private final JcaTlsCrypto crypto;
    private final PublicKey publicKey;
    private Signature rawVerifier = null;

    public JcaTlsRSAVerifier(JcaTlsCrypto crypto2, PublicKey publicKey2) {
        if (crypto2 == null) {
            throw new NullPointerException("crypto");
        } else if (publicKey2 == null) {
            throw new NullPointerException("publicKey");
        } else {
            this.crypto = crypto2;
            this.publicKey = publicKey2;
        }
    }

    @Override // com.mi.car.jsse.easysec.tls.crypto.TlsVerifier
    public TlsStreamVerifier getStreamVerifier(DigitallySigned signature) throws IOException {
        SignatureAndHashAlgorithm algorithm = signature.getAlgorithm();
        if (algorithm == null || algorithm.getSignature() != 1 || !JcaUtils.isSunMSCAPIProviderActive() || !isSunMSCAPIRawVerifier()) {
            return null;
        }
        return this.crypto.createStreamVerifier(signature, this.publicKey);
    }

    @Override // com.mi.car.jsse.easysec.tls.crypto.TlsVerifier
    public boolean verifyRawSignature(DigitallySigned signedParams, byte[] hash) throws IOException {
        SignatureAndHashAlgorithm algorithm = signedParams.getAlgorithm();
        try {
            Signature verifier = getRawVerifier();
            if (algorithm == null) {
                verifier.update(hash, 0, hash.length);
            } else if (algorithm.getSignature() != 1) {
                throw new IllegalStateException("Invalid algorithm: " + algorithm);
            } else {
                byte[] digestInfo = new DigestInfo(new AlgorithmIdentifier(TlsUtils.getOIDForHashAlgorithm(algorithm.getHash()), DERNull.INSTANCE), hash).getEncoded();
                verifier.update(digestInfo, 0, digestInfo.length);
            }
            return verifier.verify(signedParams.getSignature());
        } catch (GeneralSecurityException e) {
            throw Exceptions.illegalStateException("unable to process signature: " + e.getMessage(), e);
        }
    }

    /* access modifiers changed from: protected */
    public Signature getRawVerifier() throws GeneralSecurityException {
        if (this.rawVerifier == null) {
            this.rawVerifier = this.crypto.getHelper().createSignature("NoneWithRSA");
            this.rawVerifier.initVerify(this.publicKey);
        }
        return this.rawVerifier;
    }

    /* access modifiers changed from: protected */
    public boolean isSunMSCAPIRawVerifier() throws IOException {
        try {
            return JcaUtils.isSunMSCAPIProvider(getRawVerifier().getProvider());
        } catch (GeneralSecurityException e) {
            return true;
        }
    }
}
