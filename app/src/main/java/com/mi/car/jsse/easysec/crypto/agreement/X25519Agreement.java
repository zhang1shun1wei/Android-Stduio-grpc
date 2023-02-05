package com.mi.car.jsse.easysec.crypto.agreement;

import com.mi.car.jsse.easysec.crypto.CipherParameters;
import com.mi.car.jsse.easysec.crypto.RawAgreement;
import com.mi.car.jsse.easysec.crypto.params.X25519PrivateKeyParameters;
import com.mi.car.jsse.easysec.crypto.params.X25519PublicKeyParameters;

public final class X25519Agreement implements RawAgreement {
    private X25519PrivateKeyParameters privateKey;

    @Override // com.mi.car.jsse.easysec.crypto.RawAgreement
    public void init(CipherParameters parameters) {
        this.privateKey = (X25519PrivateKeyParameters) parameters;
    }

    @Override // com.mi.car.jsse.easysec.crypto.RawAgreement
    public int getAgreementSize() {
        return 32;
    }

    @Override // com.mi.car.jsse.easysec.crypto.RawAgreement
    public void calculateAgreement(CipherParameters publicKey, byte[] buf, int off) {
        this.privateKey.generateSecret((X25519PublicKeyParameters) publicKey, buf, off);
    }
}
