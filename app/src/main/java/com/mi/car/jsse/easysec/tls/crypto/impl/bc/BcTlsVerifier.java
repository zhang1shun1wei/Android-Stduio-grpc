package com.mi.car.jsse.easysec.tls.crypto.impl.bc;

import com.mi.car.jsse.easysec.crypto.params.AsymmetricKeyParameter;
import com.mi.car.jsse.easysec.tls.DigitallySigned;
import com.mi.car.jsse.easysec.tls.crypto.TlsStreamVerifier;
import com.mi.car.jsse.easysec.tls.crypto.TlsVerifier;

public abstract class BcTlsVerifier implements TlsVerifier {
    protected final BcTlsCrypto crypto;
    protected final AsymmetricKeyParameter publicKey;

    protected BcTlsVerifier(BcTlsCrypto crypto2, AsymmetricKeyParameter publicKey2) {
        if (crypto2 == null) {
            throw new NullPointerException("'crypto' cannot be null");
        } else if (publicKey2 == null) {
            throw new NullPointerException("'publicKey' cannot be null");
        } else if (publicKey2.isPrivate()) {
            throw new IllegalArgumentException("'publicKey' must be public");
        } else {
            this.crypto = crypto2;
            this.publicKey = publicKey2;
        }
    }

    @Override // com.mi.car.jsse.easysec.tls.crypto.TlsVerifier
    public TlsStreamVerifier getStreamVerifier(DigitallySigned signature) {
        return null;
    }
}
