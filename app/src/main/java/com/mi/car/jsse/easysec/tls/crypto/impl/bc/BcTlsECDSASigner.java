package com.mi.car.jsse.easysec.tls.crypto.impl.bc;

import com.mi.car.jsse.easysec.crypto.DSA;
import com.mi.car.jsse.easysec.crypto.params.ECPrivateKeyParameters;
import com.mi.car.jsse.easysec.crypto.signers.ECDSASigner;
import com.mi.car.jsse.easysec.crypto.signers.HMacDSAKCalculator;

public class BcTlsECDSASigner extends BcTlsDSSSigner {
    public BcTlsECDSASigner(BcTlsCrypto crypto, ECPrivateKeyParameters privateKey) {
        super(crypto, privateKey);
    }

    /* access modifiers changed from: protected */
    @Override // com.mi.car.jsse.easysec.tls.crypto.impl.bc.BcTlsDSSSigner
    public DSA createDSAImpl(int cryptoHashAlgorithm) {
        return new ECDSASigner(new HMacDSAKCalculator(this.crypto.createDigest(cryptoHashAlgorithm)));
    }

    /* access modifiers changed from: protected */
    @Override // com.mi.car.jsse.easysec.tls.crypto.impl.bc.BcTlsDSSSigner
    public short getSignatureAlgorithm() {
        return 3;
    }
}
