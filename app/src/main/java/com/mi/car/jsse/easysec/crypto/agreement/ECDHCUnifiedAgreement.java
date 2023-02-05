package com.mi.car.jsse.easysec.crypto.agreement;

import com.mi.car.jsse.easysec.crypto.CipherParameters;
import com.mi.car.jsse.easysec.crypto.params.ECDHUPrivateParameters;
import com.mi.car.jsse.easysec.crypto.params.ECDHUPublicParameters;
import com.mi.car.jsse.easysec.util.BigIntegers;
import java.math.BigInteger;

public class ECDHCUnifiedAgreement {
    private ECDHUPrivateParameters privParams;

    public void init(CipherParameters key) {
        this.privParams = (ECDHUPrivateParameters) key;
    }

    public int getFieldSize() {
        return (this.privParams.getStaticPrivateKey().getParameters().getCurve().getFieldSize() + 7) / 8;
    }

    public byte[] calculateAgreement(CipherParameters pubKey) {
        ECDHUPublicParameters pubParams = (ECDHUPublicParameters) pubKey;
        ECDHCBasicAgreement sAgree = new ECDHCBasicAgreement();
        ECDHCBasicAgreement eAgree = new ECDHCBasicAgreement();
        sAgree.init(this.privParams.getStaticPrivateKey());
        BigInteger sComp = sAgree.calculateAgreement(pubParams.getStaticPublicKey());
        eAgree.init(this.privParams.getEphemeralPrivateKey());
        BigInteger eComp = eAgree.calculateAgreement(pubParams.getEphemeralPublicKey());
        int fieldSize = getFieldSize();
        byte[] result = new byte[(fieldSize * 2)];
        BigIntegers.asUnsignedByteArray(eComp, result, 0, fieldSize);
        BigIntegers.asUnsignedByteArray(sComp, result, fieldSize, fieldSize);
        return result;
    }
}
