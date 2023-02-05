package com.mi.car.jsse.easysec.crypto.agreement;

import com.mi.car.jsse.easysec.crypto.CipherParameters;
import com.mi.car.jsse.easysec.crypto.RawAgreement;
import com.mi.car.jsse.easysec.crypto.params.X448PrivateKeyParameters;
import com.mi.car.jsse.easysec.crypto.params.X448PublicKeyParameters;

public final class X448Agreement implements RawAgreement {
    private X448PrivateKeyParameters privateKey;

    @Override // com.mi.car.jsse.easysec.crypto.RawAgreement
    public void init(CipherParameters parameters) {
        this.privateKey = (X448PrivateKeyParameters) parameters;
    }

    @Override // com.mi.car.jsse.easysec.crypto.RawAgreement
    public int getAgreementSize() {
        return 56;
    }

    @Override // com.mi.car.jsse.easysec.crypto.RawAgreement
    public void calculateAgreement(CipherParameters publicKey, byte[] buf, int off) {
        this.privateKey.generateSecret((X448PublicKeyParameters) publicKey, buf, off);
    }
}
