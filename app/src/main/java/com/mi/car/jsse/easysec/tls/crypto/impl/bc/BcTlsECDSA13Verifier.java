package com.mi.car.jsse.easysec.tls.crypto.impl.bc;

import com.mi.car.jsse.easysec.crypto.Signer;
import com.mi.car.jsse.easysec.crypto.digests.NullDigest;
import com.mi.car.jsse.easysec.crypto.params.ECPublicKeyParameters;
import com.mi.car.jsse.easysec.crypto.signers.DSADigestSigner;
import com.mi.car.jsse.easysec.crypto.signers.ECDSASigner;
import com.mi.car.jsse.easysec.crypto.signers.HMacDSAKCalculator;
import com.mi.car.jsse.easysec.tls.DigitallySigned;
import com.mi.car.jsse.easysec.tls.SignatureAndHashAlgorithm;
import com.mi.car.jsse.easysec.tls.SignatureScheme;

public class BcTlsECDSA13Verifier extends BcTlsVerifier {
    private final int signatureScheme;

    public BcTlsECDSA13Verifier(BcTlsCrypto crypto, ECPublicKeyParameters publicKey, int signatureScheme2) {
        super(crypto, publicKey);
        if (!SignatureScheme.isECDSA(signatureScheme2)) {
            throw new IllegalArgumentException("signatureScheme");
        }
        this.signatureScheme = signatureScheme2;
    }

    @Override // com.mi.car.jsse.easysec.tls.crypto.TlsVerifier
    public boolean verifyRawSignature(DigitallySigned signature, byte[] hash) {
        SignatureAndHashAlgorithm algorithm = signature.getAlgorithm();
        if (algorithm == null || SignatureScheme.from(algorithm) != this.signatureScheme) {
            throw new IllegalStateException("Invalid algorithm: " + algorithm);
        }
        Signer signer = new DSADigestSigner(new ECDSASigner(new HMacDSAKCalculator(this.crypto.createDigest(SignatureScheme.getCryptoHashAlgorithm(this.signatureScheme)))), new NullDigest());
        signer.init(false, this.publicKey);
        signer.update(hash, 0, hash.length);
        return signer.verifySignature(signature.getSignature());
    }
}
