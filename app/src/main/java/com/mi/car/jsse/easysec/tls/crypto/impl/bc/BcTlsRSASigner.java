package com.mi.car.jsse.easysec.tls.crypto.impl.bc;

import com.mi.car.jsse.easysec.crypto.CryptoException;
import com.mi.car.jsse.easysec.crypto.Digest;
import com.mi.car.jsse.easysec.crypto.Signer;
import com.mi.car.jsse.easysec.crypto.digests.NullDigest;
import com.mi.car.jsse.easysec.crypto.encodings.PKCS1Encoding;
import com.mi.car.jsse.easysec.crypto.engines.RSABlindedEngine;
import com.mi.car.jsse.easysec.crypto.params.ParametersWithRandom;
import com.mi.car.jsse.easysec.crypto.params.RSAKeyParameters;
import com.mi.car.jsse.easysec.crypto.signers.GenericSigner;
import com.mi.car.jsse.easysec.crypto.signers.RSADigestSigner;
import com.mi.car.jsse.easysec.tls.SignatureAndHashAlgorithm;
import com.mi.car.jsse.easysec.tls.TlsFatalAlert;
import com.mi.car.jsse.easysec.tls.TlsUtils;
import java.io.IOException;

public class BcTlsRSASigner extends BcTlsSigner {
    private final RSAKeyParameters publicKey;

    public BcTlsRSASigner(BcTlsCrypto crypto, RSAKeyParameters privateKey, RSAKeyParameters publicKey2) {
        super(crypto, privateKey);
        this.publicKey = publicKey2;
    }

    @Override // com.mi.car.jsse.easysec.tls.crypto.TlsSigner
    public byte[] generateRawSignature(SignatureAndHashAlgorithm algorithm, byte[] hash) throws IOException {
        Signer signer;
        Digest nullDigest = new NullDigest();
        if (algorithm == null) {
            signer = new GenericSigner(new PKCS1Encoding(new RSABlindedEngine()), nullDigest);
        } else if (algorithm.getSignature() != 1) {
            throw new IllegalStateException("Invalid algorithm: " + algorithm);
        } else {
            signer = new RSADigestSigner(nullDigest, TlsUtils.getOIDForHashAlgorithm(algorithm.getHash()));
        }
        signer.init(true, new ParametersWithRandom(this.privateKey, this.crypto.getSecureRandom()));
        signer.update(hash, 0, hash.length);
        try {
            byte[] signature = signer.generateSignature();
            signer.init(false, this.publicKey);
            signer.update(hash, 0, hash.length);
            if (signer.verifySignature(signature)) {
                return signature;
            }
            throw new TlsFatalAlert((short) 80);
        } catch (CryptoException e) {
            throw new TlsFatalAlert((short) 80, (Throwable) e);
        }
    }
}
