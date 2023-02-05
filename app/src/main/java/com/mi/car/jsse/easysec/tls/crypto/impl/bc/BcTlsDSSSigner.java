package com.mi.car.jsse.easysec.tls.crypto.impl.bc;

import com.mi.car.jsse.easysec.crypto.CryptoException;
import com.mi.car.jsse.easysec.crypto.DSA;
import com.mi.car.jsse.easysec.crypto.Signer;
import com.mi.car.jsse.easysec.crypto.digests.NullDigest;
import com.mi.car.jsse.easysec.crypto.params.AsymmetricKeyParameter;
import com.mi.car.jsse.easysec.crypto.params.ParametersWithRandom;
import com.mi.car.jsse.easysec.crypto.signers.DSADigestSigner;
import com.mi.car.jsse.easysec.tls.SignatureAndHashAlgorithm;
import com.mi.car.jsse.easysec.tls.TlsFatalAlert;
import com.mi.car.jsse.easysec.tls.crypto.TlsCryptoUtils;
import java.io.IOException;

public abstract class BcTlsDSSSigner extends BcTlsSigner {
    /* access modifiers changed from: protected */
    public abstract DSA createDSAImpl(int i);

    /* access modifiers changed from: protected */
    public abstract short getSignatureAlgorithm();

    protected BcTlsDSSSigner(BcTlsCrypto crypto, AsymmetricKeyParameter privateKey) {
        super(crypto, privateKey);
    }

    @Override // com.mi.car.jsse.easysec.tls.crypto.TlsSigner
    public byte[] generateRawSignature(SignatureAndHashAlgorithm algorithm, byte[] hash) throws IOException {
        int cryptoHashAlgorithm;
        if (algorithm == null || algorithm.getSignature() == getSignatureAlgorithm()) {
            if (algorithm == null) {
                cryptoHashAlgorithm = 2;
            } else {
                cryptoHashAlgorithm = TlsCryptoUtils.getHash(algorithm.getHash());
            }
            Signer signer = new DSADigestSigner(createDSAImpl(cryptoHashAlgorithm), new NullDigest());
            signer.init(true, new ParametersWithRandom(this.privateKey, this.crypto.getSecureRandom()));
            if (algorithm == null) {
                signer.update(hash, 16, 20);
            } else {
                signer.update(hash, 0, hash.length);
            }
            try {
                return signer.generateSignature();
            } catch (CryptoException e) {
                throw new TlsFatalAlert((short) 80, (Throwable) e);
            }
        } else {
            throw new IllegalStateException("Invalid algorithm: " + algorithm);
        }
    }
}
