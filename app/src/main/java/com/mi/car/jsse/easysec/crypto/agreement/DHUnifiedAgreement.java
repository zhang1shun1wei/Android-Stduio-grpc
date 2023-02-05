package com.mi.car.jsse.easysec.crypto.agreement;

import com.mi.car.jsse.easysec.crypto.CipherParameters;
import com.mi.car.jsse.easysec.crypto.params.DHUPrivateParameters;
import com.mi.car.jsse.easysec.crypto.params.DHUPublicParameters;
import com.mi.car.jsse.easysec.util.BigIntegers;
import java.math.BigInteger;

public class DHUnifiedAgreement {
    private DHUPrivateParameters privParams;

    public void init(CipherParameters key) {
        this.privParams = (DHUPrivateParameters) key;
    }

    public int getFieldSize() {
        return (this.privParams.getStaticPrivateKey().getParameters().getP().bitLength() + 7) / 8;
    }

    public byte[] calculateAgreement(CipherParameters pubKey) {
        DHUPublicParameters pubParams = (DHUPublicParameters) pubKey;
        DHBasicAgreement sAgree = new DHBasicAgreement();
        DHBasicAgreement eAgree = new DHBasicAgreement();
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
