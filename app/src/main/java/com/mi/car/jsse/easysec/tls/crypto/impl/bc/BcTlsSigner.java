package com.mi.car.jsse.easysec.tls.crypto.impl.bc;

import com.mi.car.jsse.easysec.crypto.params.AsymmetricKeyParameter;
import com.mi.car.jsse.easysec.tls.SignatureAndHashAlgorithm;
import com.mi.car.jsse.easysec.tls.crypto.TlsSigner;
import com.mi.car.jsse.easysec.tls.crypto.TlsStreamSigner;

public abstract class BcTlsSigner implements TlsSigner {
    protected final BcTlsCrypto crypto;
    protected final AsymmetricKeyParameter privateKey;

    protected BcTlsSigner(BcTlsCrypto crypto2, AsymmetricKeyParameter privateKey2) {
        if (crypto2 == null) {
            throw new NullPointerException("'crypto' cannot be null");
        } else if (privateKey2 == null) {
            throw new NullPointerException("'privateKey' cannot be null");
        } else if (!privateKey2.isPrivate()) {
            throw new IllegalArgumentException("'privateKey' must be private");
        } else {
            this.crypto = crypto2;
            this.privateKey = privateKey2;
        }
    }

    @Override // com.mi.car.jsse.easysec.tls.crypto.TlsSigner
    public TlsStreamSigner getStreamSigner(SignatureAndHashAlgorithm algorithm) {
        return null;
    }
}
