package com.mi.car.jsse.easysec.tls.crypto.impl.jcajce;

import com.mi.car.jsse.easysec.asn1.DERNull;
import com.mi.car.jsse.easysec.asn1.x509.AlgorithmIdentifier;
import com.mi.car.jsse.easysec.asn1.x509.DigestInfo;
import com.mi.car.jsse.easysec.tls.SignatureAndHashAlgorithm;
import com.mi.car.jsse.easysec.tls.TlsFatalAlert;
import com.mi.car.jsse.easysec.tls.TlsUtils;
import com.mi.car.jsse.easysec.tls.crypto.TlsSigner;
import com.mi.car.jsse.easysec.tls.crypto.TlsStreamSigner;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;

public class JcaTlsRSASigner implements TlsSigner {
    private final JcaTlsCrypto crypto;
    private final PrivateKey privateKey;
    private final PublicKey publicKey;
    private Signature rawSigner = null;

    public JcaTlsRSASigner(JcaTlsCrypto crypto2, PrivateKey privateKey2, PublicKey publicKey2) {
        if (crypto2 == null) {
            throw new NullPointerException("crypto");
        } else if (privateKey2 == null) {
            throw new NullPointerException("privateKey");
        } else {
            this.crypto = crypto2;
            this.privateKey = privateKey2;
            this.publicKey = publicKey2;
        }
    }

    @Override // com.mi.car.jsse.easysec.tls.crypto.TlsSigner
    public byte[] generateRawSignature(SignatureAndHashAlgorithm algorithm, byte[] hash) throws IOException {
        byte[] input;
        try {
            Signature signer = getRawSigner();
            if (algorithm == null) {
                input = hash;
            } else if (algorithm.getSignature() != 1) {
                throw new IllegalStateException("Invalid algorithm: " + algorithm);
            } else {
                input = new DigestInfo(new AlgorithmIdentifier(TlsUtils.getOIDForHashAlgorithm(algorithm.getHash()), DERNull.INSTANCE), hash).getEncoded();
            }
            signer.update(input, 0, input.length);
            byte[] signature = signer.sign();
            signer.initVerify(this.publicKey);
            signer.update(input, 0, input.length);
            if (signer.verify(signature)) {
                this.rawSigner = null;
                return signature;
            }
            this.rawSigner = null;
            throw new TlsFatalAlert((short) 80);
        } catch (GeneralSecurityException e) {
            throw new TlsFatalAlert((short) 80, (Throwable) e);
        } catch (Throwable th) {
            this.rawSigner = null;
            throw th;
        }
    }

    @Override // com.mi.car.jsse.easysec.tls.crypto.TlsSigner
    public TlsStreamSigner getStreamSigner(SignatureAndHashAlgorithm algorithm) throws IOException {
        if (algorithm == null || 1 != algorithm.getSignature() || !JcaUtils.isSunMSCAPIProviderActive() || !isSunMSCAPIRawSigner()) {
            return null;
        }
        return this.crypto.createVerifyingStreamSigner(algorithm, this.privateKey, true, this.publicKey);
    }

    /* access modifiers changed from: protected */
    public Signature getRawSigner() throws GeneralSecurityException {
        if (this.rawSigner == null) {
            this.rawSigner = this.crypto.getHelper().createSignature("NoneWithRSA");
            this.rawSigner.initSign(this.privateKey, this.crypto.getSecureRandom());
        }
        return this.rawSigner;
    }

    /* access modifiers changed from: protected */
    public boolean isSunMSCAPIRawSigner() throws IOException {
        try {
            return JcaUtils.isSunMSCAPIProvider(getRawSigner().getProvider());
        } catch (GeneralSecurityException e) {
            return true;
        }
    }
}
