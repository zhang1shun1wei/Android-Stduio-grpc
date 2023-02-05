package com.mi.car.jsse.easysec.tls.crypto.impl.bc;

import com.mi.car.jsse.easysec.crypto.Digest;
import com.mi.car.jsse.easysec.crypto.Signer;
import com.mi.car.jsse.easysec.crypto.digests.NullDigest;
import com.mi.car.jsse.easysec.crypto.encodings.PKCS1Encoding;
import com.mi.car.jsse.easysec.crypto.engines.RSABlindedEngine;
import com.mi.car.jsse.easysec.crypto.params.RSAKeyParameters;
import com.mi.car.jsse.easysec.crypto.signers.GenericSigner;
import com.mi.car.jsse.easysec.crypto.signers.RSADigestSigner;
import com.mi.car.jsse.easysec.tls.DigitallySigned;
import com.mi.car.jsse.easysec.tls.SignatureAndHashAlgorithm;
import com.mi.car.jsse.easysec.tls.TlsUtils;

public class BcTlsRSAVerifier extends BcTlsVerifier {
    public BcTlsRSAVerifier(BcTlsCrypto crypto, RSAKeyParameters publicKey) {
        super(crypto, publicKey);
    }

    @Override // com.mi.car.jsse.easysec.tls.crypto.TlsVerifier
    public boolean verifyRawSignature(DigitallySigned signedParams, byte[] hash) {
        Signer signer;
        Digest nullDigest = new NullDigest();
        SignatureAndHashAlgorithm algorithm = signedParams.getAlgorithm();
        if (algorithm == null) {
            signer = new GenericSigner(new PKCS1Encoding(new RSABlindedEngine()), nullDigest);
        } else if (algorithm.getSignature() != 1) {
            throw new IllegalStateException("Invalid algorithm: " + algorithm);
        } else {
            signer = new RSADigestSigner(nullDigest, TlsUtils.getOIDForHashAlgorithm(algorithm.getHash()));
        }
        signer.init(false, this.publicKey);
        signer.update(hash, 0, hash.length);
        return signer.verifySignature(signedParams.getSignature());
    }
}
