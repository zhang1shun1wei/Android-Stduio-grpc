package com.mi.car.jsse.easysec.crypto.agreement;

import com.mi.car.jsse.easysec.crypto.CipherParameters;
import com.mi.car.jsse.easysec.crypto.RawAgreement;
import com.mi.car.jsse.easysec.crypto.params.XDHUPrivateParameters;
import com.mi.car.jsse.easysec.crypto.params.XDHUPublicParameters;

public class XDHUnifiedAgreement implements RawAgreement {
    private XDHUPrivateParameters privParams;
    private final RawAgreement xAgreement;

    public XDHUnifiedAgreement(RawAgreement xAgreement2) {
        this.xAgreement = xAgreement2;
    }

    @Override // com.mi.car.jsse.easysec.crypto.RawAgreement
    public void init(CipherParameters key) {
        this.privParams = (XDHUPrivateParameters) key;
    }

    @Override // com.mi.car.jsse.easysec.crypto.RawAgreement
    public int getAgreementSize() {
        return this.xAgreement.getAgreementSize() * 2;
    }

    @Override // com.mi.car.jsse.easysec.crypto.RawAgreement
    public void calculateAgreement(CipherParameters publicKey, byte[] buf, int off) {
        XDHUPublicParameters pubParams = (XDHUPublicParameters) publicKey;
        this.xAgreement.init(this.privParams.getEphemeralPrivateKey());
        this.xAgreement.calculateAgreement(pubParams.getEphemeralPublicKey(), buf, off);
        this.xAgreement.init(this.privParams.getStaticPrivateKey());
        this.xAgreement.calculateAgreement(pubParams.getStaticPublicKey(), buf, this.xAgreement.getAgreementSize() + off);
    }
}
