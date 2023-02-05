package com.mi.car.jsse.easysec.tls.crypto.impl.bc;

import com.mi.car.jsse.easysec.crypto.params.Ed25519PrivateKeyParameters;
import com.mi.car.jsse.easysec.crypto.signers.Ed25519Signer;
import com.mi.car.jsse.easysec.tls.SignatureAndHashAlgorithm;
import com.mi.car.jsse.easysec.tls.SignatureScheme;
import com.mi.car.jsse.easysec.tls.crypto.TlsStreamSigner;
import java.io.IOException;

public class BcTlsEd25519Signer extends BcTlsSigner {
    public BcTlsEd25519Signer(BcTlsCrypto crypto, Ed25519PrivateKeyParameters privateKey) {
        super(crypto, privateKey);
    }

    @Override // com.mi.car.jsse.easysec.tls.crypto.TlsSigner
    public byte[] generateRawSignature(SignatureAndHashAlgorithm algorithm, byte[] hash) throws IOException {
        throw new UnsupportedOperationException();
    }

    @Override // com.mi.car.jsse.easysec.tls.crypto.impl.bc.BcTlsSigner, com.mi.car.jsse.easysec.tls.crypto.TlsSigner
    public TlsStreamSigner getStreamSigner(SignatureAndHashAlgorithm algorithm) {
        if (algorithm == null || SignatureScheme.from(algorithm) != 2055) {
            throw new IllegalStateException("Invalid algorithm: " + algorithm);
        }
        Ed25519Signer signer = new Ed25519Signer();
        signer.init(true, this.privateKey);
        return new BcTlsStreamSigner(signer);
    }
}
