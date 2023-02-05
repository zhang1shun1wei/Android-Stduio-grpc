package com.mi.car.jsse.easysec.tls.crypto.impl.bc;

import com.mi.car.jsse.easysec.crypto.params.Ed448PrivateKeyParameters;
import com.mi.car.jsse.easysec.crypto.signers.Ed448Signer;
import com.mi.car.jsse.easysec.tls.SignatureAndHashAlgorithm;
import com.mi.car.jsse.easysec.tls.SignatureScheme;
import com.mi.car.jsse.easysec.tls.TlsUtils;
import com.mi.car.jsse.easysec.tls.crypto.TlsStreamSigner;
import java.io.IOException;

public class BcTlsEd448Signer extends BcTlsSigner {
    public BcTlsEd448Signer(BcTlsCrypto crypto, Ed448PrivateKeyParameters privateKey) {
        super(crypto, privateKey);
    }

    @Override // com.mi.car.jsse.easysec.tls.crypto.TlsSigner
    public byte[] generateRawSignature(SignatureAndHashAlgorithm algorithm, byte[] hash) throws IOException {
        throw new UnsupportedOperationException();
    }

    @Override // com.mi.car.jsse.easysec.tls.crypto.impl.bc.BcTlsSigner, com.mi.car.jsse.easysec.tls.crypto.TlsSigner
    public TlsStreamSigner getStreamSigner(SignatureAndHashAlgorithm algorithm) {
        if (algorithm == null || SignatureScheme.from(algorithm) != 2056) {
            throw new IllegalStateException("Invalid algorithm: " + algorithm);
        }
        Ed448Signer signer = new Ed448Signer(TlsUtils.EMPTY_BYTES);
        signer.init(true, this.privateKey);
        return new BcTlsStreamSigner(signer);
    }
}
