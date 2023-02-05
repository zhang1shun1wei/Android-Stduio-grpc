package com.mi.car.jsse.easysec.tls.crypto.impl.bc;

import com.mi.car.jsse.easysec.crypto.Digest;
import com.mi.car.jsse.easysec.crypto.engines.RSAEngine;
import com.mi.car.jsse.easysec.crypto.params.RSAKeyParameters;
import com.mi.car.jsse.easysec.crypto.signers.PSSSigner;
import com.mi.car.jsse.easysec.tls.DigitallySigned;
import com.mi.car.jsse.easysec.tls.SignatureAndHashAlgorithm;
import com.mi.car.jsse.easysec.tls.SignatureScheme;
import com.mi.car.jsse.easysec.tls.crypto.TlsStreamVerifier;
import java.io.IOException;

public class BcTlsRSAPSSVerifier extends BcTlsVerifier {
    private final int signatureScheme;

    public BcTlsRSAPSSVerifier(BcTlsCrypto crypto, RSAKeyParameters publicKey, int signatureScheme2) {
        super(crypto, publicKey);
        if (!SignatureScheme.isRSAPSS(signatureScheme2)) {
            throw new IllegalArgumentException("signatureScheme");
        }
        this.signatureScheme = signatureScheme2;
    }

    @Override // com.mi.car.jsse.easysec.tls.crypto.TlsVerifier
    public boolean verifyRawSignature(DigitallySigned signature, byte[] hash) throws IOException {
        throw new UnsupportedOperationException();
    }

    @Override // com.mi.car.jsse.easysec.tls.crypto.impl.bc.BcTlsVerifier, com.mi.car.jsse.easysec.tls.crypto.TlsVerifier
    public TlsStreamVerifier getStreamVerifier(DigitallySigned signature) {
        SignatureAndHashAlgorithm algorithm = signature.getAlgorithm();
        if (algorithm == null || SignatureScheme.from(algorithm) != this.signatureScheme) {
            throw new IllegalStateException("Invalid algorithm: " + algorithm);
        }
        Digest digest = this.crypto.createDigest(SignatureScheme.getCryptoHashAlgorithm(this.signatureScheme));
        PSSSigner verifier = new PSSSigner(new RSAEngine(), digest, digest.getDigestSize());
        verifier.init(false, this.publicKey);
        return new BcTlsStreamVerifier(verifier, signature.getSignature());
    }
}
