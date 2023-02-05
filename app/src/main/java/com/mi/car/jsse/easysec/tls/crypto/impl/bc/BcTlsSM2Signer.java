package com.mi.car.jsse.easysec.tls.crypto.impl.bc;

import com.mi.car.jsse.easysec.crypto.params.ECPrivateKeyParameters;
import com.mi.car.jsse.easysec.crypto.params.ParametersWithID;
import com.mi.car.jsse.easysec.crypto.params.ParametersWithRandom;
import com.mi.car.jsse.easysec.crypto.signers.SM2Signer;
import com.mi.car.jsse.easysec.tls.SignatureAndHashAlgorithm;
import com.mi.car.jsse.easysec.tls.crypto.TlsStreamSigner;
import com.mi.car.jsse.easysec.util.Arrays;
import java.io.IOException;

public class BcTlsSM2Signer extends BcTlsSigner {
    protected final byte[] identifier;

    public BcTlsSM2Signer(BcTlsCrypto crypto, ECPrivateKeyParameters privateKey, byte[] identifier2) {
        super(crypto, privateKey);
        this.identifier = Arrays.clone(identifier2);
    }

    @Override // com.mi.car.jsse.easysec.tls.crypto.TlsSigner
    public byte[] generateRawSignature(SignatureAndHashAlgorithm algorithm, byte[] hash) throws IOException {
        throw new UnsupportedOperationException();
    }

    @Override // com.mi.car.jsse.easysec.tls.crypto.impl.bc.BcTlsSigner, com.mi.car.jsse.easysec.tls.crypto.TlsSigner
    public TlsStreamSigner getStreamSigner(SignatureAndHashAlgorithm algorithm) {
        if (algorithm == null) {
            throw new IllegalStateException("Invalid algorithm: " + algorithm);
        }
        ParametersWithID parametersWithID = new ParametersWithID(new ParametersWithRandom(this.privateKey, this.crypto.getSecureRandom()), this.identifier);
        SM2Signer signer = new SM2Signer();
        signer.init(true, parametersWithID);
        return new BcTlsStreamSigner(signer);
    }
}
