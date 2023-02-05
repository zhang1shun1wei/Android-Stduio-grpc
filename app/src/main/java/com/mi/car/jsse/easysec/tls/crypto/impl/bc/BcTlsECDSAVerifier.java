package com.mi.car.jsse.easysec.tls.crypto.impl.bc;

import com.mi.car.jsse.easysec.crypto.DSA;
import com.mi.car.jsse.easysec.crypto.params.ECPublicKeyParameters;
import com.mi.car.jsse.easysec.crypto.signers.ECDSASigner;
import com.mi.car.jsse.easysec.crypto.signers.HMacDSAKCalculator;

public class BcTlsECDSAVerifier extends BcTlsDSSVerifier {
    public BcTlsECDSAVerifier(BcTlsCrypto crypto, ECPublicKeyParameters publicKey) {
        super(crypto, publicKey);
    }

    /* access modifiers changed from: protected */
    @Override // com.mi.car.jsse.easysec.tls.crypto.impl.bc.BcTlsDSSVerifier
    public DSA createDSAImpl(int cryptoHashAlgorithm) {
        return new ECDSASigner(new HMacDSAKCalculator(this.crypto.createDigest(cryptoHashAlgorithm)));
    }

    /* access modifiers changed from: protected */
    @Override // com.mi.car.jsse.easysec.tls.crypto.impl.bc.BcTlsDSSVerifier
    public short getSignatureAlgorithm() {
        return 3;
    }
}
