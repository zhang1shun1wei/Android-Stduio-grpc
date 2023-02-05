package com.mi.car.jsse.easysec.tls.crypto.impl.bc;

import com.mi.car.jsse.easysec.tls.crypto.TlsAgreement;
import com.mi.car.jsse.easysec.tls.crypto.TlsECDomain;

public class BcX448Domain implements TlsECDomain {
    protected final BcTlsCrypto crypto;

    public BcX448Domain(BcTlsCrypto crypto2) {
        this.crypto = crypto2;
    }

    @Override // com.mi.car.jsse.easysec.tls.crypto.TlsECDomain
    public TlsAgreement createECDH() {
        return new BcX448(this.crypto);
    }
}
