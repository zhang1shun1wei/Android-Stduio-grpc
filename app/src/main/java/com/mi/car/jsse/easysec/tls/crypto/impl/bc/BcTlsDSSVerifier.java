package com.mi.car.jsse.easysec.tls.crypto.impl.bc;

import com.mi.car.jsse.easysec.crypto.DSA;
import com.mi.car.jsse.easysec.crypto.Signer;
import com.mi.car.jsse.easysec.crypto.digests.NullDigest;
import com.mi.car.jsse.easysec.crypto.params.AsymmetricKeyParameter;
import com.mi.car.jsse.easysec.crypto.signers.DSADigestSigner;
import com.mi.car.jsse.easysec.tls.DigitallySigned;
import com.mi.car.jsse.easysec.tls.SignatureAndHashAlgorithm;
import com.mi.car.jsse.easysec.tls.crypto.TlsCryptoUtils;

public abstract class BcTlsDSSVerifier extends BcTlsVerifier {
    /* access modifiers changed from: protected */
    public abstract DSA createDSAImpl(int i);

    /* access modifiers changed from: protected */
    public abstract short getSignatureAlgorithm();

    protected BcTlsDSSVerifier(BcTlsCrypto crypto, AsymmetricKeyParameter publicKey) {
        super(crypto, publicKey);
    }

    @Override // com.mi.car.jsse.easysec.tls.crypto.TlsVerifier
    public boolean verifyRawSignature(DigitallySigned signedParams, byte[] hash) {
        int cryptoHashAlgorithm;
        SignatureAndHashAlgorithm algorithm = signedParams.getAlgorithm();
        if (algorithm == null || algorithm.getSignature() == getSignatureAlgorithm()) {
            if (algorithm == null) {
                cryptoHashAlgorithm = 2;
            } else {
                cryptoHashAlgorithm = TlsCryptoUtils.getHash(algorithm.getHash());
            }
            Signer signer = new DSADigestSigner(createDSAImpl(cryptoHashAlgorithm), new NullDigest());
            signer.init(false, this.publicKey);
            if (algorithm == null) {
                signer.update(hash, 16, 20);
            } else {
                signer.update(hash, 0, hash.length);
            }
            return signer.verifySignature(signedParams.getSignature());
        }
        throw new IllegalStateException("Invalid algorithm: " + algorithm);
    }
}
