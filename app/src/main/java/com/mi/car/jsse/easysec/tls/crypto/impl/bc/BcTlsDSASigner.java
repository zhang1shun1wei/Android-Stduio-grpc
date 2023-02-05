package com.mi.car.jsse.easysec.tls.crypto.impl.bc;

import com.mi.car.jsse.easysec.crypto.DSA;
import com.mi.car.jsse.easysec.crypto.params.DSAPrivateKeyParameters;
import com.mi.car.jsse.easysec.crypto.signers.DSASigner;
import com.mi.car.jsse.easysec.crypto.signers.HMacDSAKCalculator;

public class BcTlsDSASigner extends BcTlsDSSSigner {
    public BcTlsDSASigner(BcTlsCrypto crypto, DSAPrivateKeyParameters privateKey) {
        super(crypto, privateKey);
    }

    /* access modifiers changed from: protected */
    @Override // com.mi.car.jsse.easysec.tls.crypto.impl.bc.BcTlsDSSSigner
    public DSA createDSAImpl(int cryptoHashAlgorithm) {
        return new DSASigner(new HMacDSAKCalculator(this.crypto.createDigest(cryptoHashAlgorithm)));
    }

    /* access modifiers changed from: protected */
    @Override // com.mi.car.jsse.easysec.tls.crypto.impl.bc.BcTlsDSSSigner
    public short getSignatureAlgorithm() {
        return 2;
    }
}
