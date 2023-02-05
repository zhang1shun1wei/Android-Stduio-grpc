package com.mi.car.jsse.easysec.tls.crypto.impl.bc;

import com.mi.car.jsse.easysec.crypto.CryptoException;
import com.mi.car.jsse.easysec.crypto.Signer;
import com.mi.car.jsse.easysec.crypto.digests.NullDigest;
import com.mi.car.jsse.easysec.crypto.params.ECPrivateKeyParameters;
import com.mi.car.jsse.easysec.crypto.params.ParametersWithRandom;
import com.mi.car.jsse.easysec.crypto.signers.DSADigestSigner;
import com.mi.car.jsse.easysec.crypto.signers.ECDSASigner;
import com.mi.car.jsse.easysec.crypto.signers.HMacDSAKCalculator;
import com.mi.car.jsse.easysec.tls.SignatureAndHashAlgorithm;
import com.mi.car.jsse.easysec.tls.SignatureScheme;
import com.mi.car.jsse.easysec.tls.TlsFatalAlert;
import java.io.IOException;

public class BcTlsECDSA13Signer extends BcTlsSigner {
    private final int signatureScheme;

    public BcTlsECDSA13Signer(BcTlsCrypto crypto, ECPrivateKeyParameters privateKey, int signatureScheme2) {
        super(crypto, privateKey);
        if (!SignatureScheme.isECDSA(signatureScheme2)) {
            throw new IllegalArgumentException("signatureScheme");
        }
        this.signatureScheme = signatureScheme2;
    }

    @Override // com.mi.car.jsse.easysec.tls.crypto.TlsSigner
    public byte[] generateRawSignature(SignatureAndHashAlgorithm algorithm, byte[] hash) throws IOException {
        if (algorithm == null || SignatureScheme.from(algorithm) != this.signatureScheme) {
            throw new IllegalStateException("Invalid algorithm: " + algorithm);
        }
        Signer signer = new DSADigestSigner(new ECDSASigner(new HMacDSAKCalculator(this.crypto.createDigest(SignatureScheme.getCryptoHashAlgorithm(this.signatureScheme)))), new NullDigest());
        signer.init(true, new ParametersWithRandom(this.privateKey, this.crypto.getSecureRandom()));
        signer.update(hash, 0, hash.length);
        try {
            return signer.generateSignature();
        } catch (CryptoException e) {
            throw new TlsFatalAlert((short) 80, (Throwable) e);
        }
    }
}
