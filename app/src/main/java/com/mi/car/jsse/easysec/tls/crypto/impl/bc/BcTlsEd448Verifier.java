package com.mi.car.jsse.easysec.tls.crypto.impl.bc;

import com.mi.car.jsse.easysec.crypto.params.Ed448PublicKeyParameters;
import com.mi.car.jsse.easysec.crypto.signers.Ed448Signer;
import com.mi.car.jsse.easysec.tls.DigitallySigned;
import com.mi.car.jsse.easysec.tls.SignatureAndHashAlgorithm;
import com.mi.car.jsse.easysec.tls.SignatureScheme;
import com.mi.car.jsse.easysec.tls.TlsUtils;
import com.mi.car.jsse.easysec.tls.crypto.TlsStreamVerifier;
import java.io.IOException;

public class BcTlsEd448Verifier extends BcTlsVerifier {
    public BcTlsEd448Verifier(BcTlsCrypto crypto, Ed448PublicKeyParameters publicKey) {
        super(crypto, publicKey);
    }

    @Override // com.mi.car.jsse.easysec.tls.crypto.TlsVerifier
    public boolean verifyRawSignature(DigitallySigned signature, byte[] hash) throws IOException {
        throw new UnsupportedOperationException();
    }

    @Override // com.mi.car.jsse.easysec.tls.crypto.impl.bc.BcTlsVerifier, com.mi.car.jsse.easysec.tls.crypto.TlsVerifier
    public TlsStreamVerifier getStreamVerifier(DigitallySigned signature) {
        SignatureAndHashAlgorithm algorithm = signature.getAlgorithm();
        if (algorithm == null || SignatureScheme.from(algorithm) != 2056) {
            throw new IllegalStateException("Invalid algorithm: " + algorithm);
        }
        Ed448Signer verifier = new Ed448Signer(TlsUtils.EMPTY_BYTES);
        verifier.init(false, this.publicKey);
        return new BcTlsStreamVerifier(verifier, signature.getSignature());
    }
}
