package com.mi.car.jsse.easysec.crypto.agreement;

import com.mi.car.jsse.easysec.crypto.CipherParameters;
import com.mi.car.jsse.easysec.crypto.StagedAgreement;
import com.mi.car.jsse.easysec.crypto.params.AsymmetricKeyParameter;
import com.mi.car.jsse.easysec.crypto.params.ECDomainParameters;
import com.mi.car.jsse.easysec.crypto.params.ECPrivateKeyParameters;
import com.mi.car.jsse.easysec.crypto.params.ECPublicKeyParameters;
import com.mi.car.jsse.easysec.math.ec.ECAlgorithms;
import com.mi.car.jsse.easysec.math.ec.ECPoint;
import java.math.BigInteger;

public class ECDHCStagedAgreement implements StagedAgreement {
    ECPrivateKeyParameters key;

    @Override // com.mi.car.jsse.easysec.crypto.BasicAgreement
    public void init(CipherParameters key2) {
        this.key = (ECPrivateKeyParameters) key2;
    }

    @Override // com.mi.car.jsse.easysec.crypto.BasicAgreement
    public int getFieldSize() {
        return (this.key.getParameters().getCurve().getFieldSize() + 7) / 8;
    }

    @Override // com.mi.car.jsse.easysec.crypto.StagedAgreement
    public AsymmetricKeyParameter calculateStage(CipherParameters pubKey) {
        return new ECPublicKeyParameters(calculateNextPoint((ECPublicKeyParameters) pubKey), this.key.getParameters());
    }

    @Override // com.mi.car.jsse.easysec.crypto.BasicAgreement
    public BigInteger calculateAgreement(CipherParameters pubKey) {
        return calculateNextPoint((ECPublicKeyParameters) pubKey).getAffineXCoord().toBigInteger();
    }

    private ECPoint calculateNextPoint(ECPublicKeyParameters pubKey) {
        ECDomainParameters params = this.key.getParameters();
        if (!params.equals(pubKey.getParameters())) {
            throw new IllegalStateException("ECDHC public key has wrong domain parameters");
        }
        BigInteger hd = params.getH().multiply(this.key.getD()).mod(params.getN());
        ECPoint pubPoint = ECAlgorithms.cleanPoint(params.getCurve(), pubKey.getQ());
        if (pubPoint.isInfinity()) {
            throw new IllegalStateException("Infinity is not a valid public key for ECDHC");
        }
        ECPoint P = pubPoint.multiply(hd).normalize();
        if (!P.isInfinity()) {
            return P;
        }
        throw new IllegalStateException("Infinity is not a valid agreement value for ECDHC");
    }
}
