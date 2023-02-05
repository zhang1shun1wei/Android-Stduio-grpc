package com.mi.car.jsse.easysec.tls.crypto.impl.bc;

import com.mi.car.jsse.easysec.crypto.DSA;
import com.mi.car.jsse.easysec.crypto.params.DSAPublicKeyParameters;
import com.mi.car.jsse.easysec.crypto.signers.DSASigner;
import com.mi.car.jsse.easysec.crypto.signers.HMacDSAKCalculator;

public class BcTlsDSAVerifier extends BcTlsDSSVerifier {
    public BcTlsDSAVerifier(BcTlsCrypto crypto, DSAPublicKeyParameters publicKey) {
        super(crypto, publicKey);
    }

    /* access modifiers changed from: protected */
    @Override // com.mi.car.jsse.easysec.tls.crypto.impl.bc.BcTlsDSSVerifier
    public DSA createDSAImpl(int cryptoHashAlgorithm) {
        return new DSASigner(new HMacDSAKCalculator(this.crypto.createDigest(cryptoHashAlgorithm)));
    }

    /* access modifiers changed from: protected */
    @Override // com.mi.car.jsse.easysec.tls.crypto.impl.bc.BcTlsDSSVerifier
    public short getSignatureAlgorithm() {
        return 2;
    }
}
