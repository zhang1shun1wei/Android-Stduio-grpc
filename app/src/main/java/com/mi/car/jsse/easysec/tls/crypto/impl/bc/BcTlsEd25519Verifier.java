package com.mi.car.jsse.easysec.tls.crypto.impl.bc;

import com.mi.car.jsse.easysec.crypto.params.Ed25519PublicKeyParameters;
import com.mi.car.jsse.easysec.crypto.signers.Ed25519Signer;
import com.mi.car.jsse.easysec.tls.DigitallySigned;
import com.mi.car.jsse.easysec.tls.SignatureAndHashAlgorithm;
import com.mi.car.jsse.easysec.tls.SignatureScheme;
import com.mi.car.jsse.easysec.tls.crypto.TlsStreamVerifier;
import java.io.IOException;

public class BcTlsEd25519Verifier extends BcTlsVerifier {
    public BcTlsEd25519Verifier(BcTlsCrypto crypto, Ed25519PublicKeyParameters publicKey) {
        super(crypto, publicKey);
    }

    @Override // com.mi.car.jsse.easysec.tls.crypto.TlsVerifier
    public boolean verifyRawSignature(DigitallySigned signature, byte[] hash) throws IOException {
        throw new UnsupportedOperationException();
    }

    @Override // com.mi.car.jsse.easysec.tls.crypto.impl.bc.BcTlsVerifier, com.mi.car.jsse.easysec.tls.crypto.TlsVerifier
    public TlsStreamVerifier getStreamVerifier(DigitallySigned signature) {
        SignatureAndHashAlgorithm algorithm = signature.getAlgorithm();
        if (algorithm == null || SignatureScheme.from(algorithm) != 2055) {
            throw new IllegalStateException("Invalid algorithm: " + algorithm);
        }
        Ed25519Signer verifier = new Ed25519Signer();
        verifier.init(false, this.publicKey);
        return new BcTlsStreamVerifier(verifier, signature.getSignature());
    }
}
