package com.mi.car.jsse.easysec.tls.crypto.impl.bc;

import com.mi.car.jsse.easysec.crypto.params.ECPublicKeyParameters;
import com.mi.car.jsse.easysec.crypto.params.ParametersWithID;
import com.mi.car.jsse.easysec.crypto.signers.SM2Signer;
import com.mi.car.jsse.easysec.tls.DigitallySigned;
import com.mi.car.jsse.easysec.tls.SignatureAndHashAlgorithm;
import com.mi.car.jsse.easysec.tls.crypto.TlsStreamVerifier;
import com.mi.car.jsse.easysec.util.Arrays;
import java.io.IOException;

public class BcTlsSM2Verifier extends BcTlsVerifier {
    protected final byte[] identifier;

    public BcTlsSM2Verifier(BcTlsCrypto crypto, ECPublicKeyParameters publicKey, byte[] identifier2) {
        super(crypto, publicKey);
        this.identifier = Arrays.clone(identifier2);
    }

    @Override // com.mi.car.jsse.easysec.tls.crypto.TlsVerifier
    public boolean verifyRawSignature(DigitallySigned signature, byte[] hash) throws IOException {
        throw new UnsupportedOperationException();
    }

    @Override // com.mi.car.jsse.easysec.tls.crypto.impl.bc.BcTlsVerifier, com.mi.car.jsse.easysec.tls.crypto.TlsVerifier
    public TlsStreamVerifier getStreamVerifier(DigitallySigned signature) {
        SignatureAndHashAlgorithm algorithm = signature.getAlgorithm();
        if (algorithm == null) {
            throw new IllegalStateException("Invalid algorithm: " + algorithm);
        }
        ParametersWithID parametersWithID = new ParametersWithID(this.publicKey, this.identifier);
        SM2Signer verifier = new SM2Signer();
        verifier.init(false, parametersWithID);
        return new BcTlsStreamVerifier(verifier, signature.getSignature());
    }
}
