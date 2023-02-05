package com.mi.car.jsse.easysec.tls.crypto.impl.bc;

import com.mi.car.jsse.easysec.crypto.Digest;
import com.mi.car.jsse.easysec.crypto.engines.RSABlindedEngine;
import com.mi.car.jsse.easysec.crypto.params.ParametersWithRandom;
import com.mi.car.jsse.easysec.crypto.params.RSAKeyParameters;
import com.mi.car.jsse.easysec.crypto.signers.PSSSigner;
import com.mi.car.jsse.easysec.tls.SignatureAndHashAlgorithm;
import com.mi.car.jsse.easysec.tls.SignatureScheme;
import com.mi.car.jsse.easysec.tls.crypto.TlsStreamSigner;
import java.io.IOException;

public class BcTlsRSAPSSSigner extends BcTlsSigner {
    private final int signatureScheme;

    public BcTlsRSAPSSSigner(BcTlsCrypto crypto, RSAKeyParameters privateKey, int signatureScheme2) {
        super(crypto, privateKey);
        if (!SignatureScheme.isRSAPSS(signatureScheme2)) {
            throw new IllegalArgumentException("signatureScheme");
        }
        this.signatureScheme = signatureScheme2;
    }

    @Override // com.mi.car.jsse.easysec.tls.crypto.TlsSigner
    public byte[] generateRawSignature(SignatureAndHashAlgorithm algorithm, byte[] hash) throws IOException {
        throw new UnsupportedOperationException();
    }

    @Override // com.mi.car.jsse.easysec.tls.crypto.impl.bc.BcTlsSigner, com.mi.car.jsse.easysec.tls.crypto.TlsSigner
    public TlsStreamSigner getStreamSigner(SignatureAndHashAlgorithm algorithm) {
        if (algorithm == null || SignatureScheme.from(algorithm) != this.signatureScheme) {
            throw new IllegalStateException("Invalid algorithm: " + algorithm);
        }
        Digest digest = this.crypto.createDigest(SignatureScheme.getCryptoHashAlgorithm(this.signatureScheme));
        PSSSigner signer = new PSSSigner(new RSABlindedEngine(), digest, digest.getDigestSize());
        signer.init(true, new ParametersWithRandom(this.privateKey, this.crypto.getSecureRandom()));
        return new BcTlsStreamSigner(signer);
    }
}
