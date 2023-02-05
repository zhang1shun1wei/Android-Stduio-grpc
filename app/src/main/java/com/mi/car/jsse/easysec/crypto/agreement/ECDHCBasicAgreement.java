package com.mi.car.jsse.easysec.crypto.agreement;

import com.mi.car.jsse.easysec.crypto.BasicAgreement;
import com.mi.car.jsse.easysec.crypto.CipherParameters;
import com.mi.car.jsse.easysec.crypto.params.ECDomainParameters;
import com.mi.car.jsse.easysec.crypto.params.ECPrivateKeyParameters;
import com.mi.car.jsse.easysec.crypto.params.ECPublicKeyParameters;
import com.mi.car.jsse.easysec.math.ec.ECAlgorithms;
import com.mi.car.jsse.easysec.math.ec.ECPoint;
import java.math.BigInteger;

public class ECDHCBasicAgreement implements BasicAgreement {
    ECPrivateKeyParameters key;

    @Override // com.mi.car.jsse.easysec.crypto.BasicAgreement
    public void init(CipherParameters key2) {
        this.key = (ECPrivateKeyParameters) key2;
    }

    @Override // com.mi.car.jsse.easysec.crypto.BasicAgreement
    public int getFieldSize() {
        return (this.key.getParameters().getCurve().getFieldSize() + 7) / 8;
    }

    @Override // com.mi.car.jsse.easysec.crypto.BasicAgreement
    public BigInteger calculateAgreement(CipherParameters pubKey) {
        ECPublicKeyParameters pub = (ECPublicKeyParameters) pubKey;
        ECDomainParameters params = this.key.getParameters();
        if (!params.equals(pub.getParameters())) {
            throw new IllegalStateException("ECDHC public key has wrong domain parameters");
        }
        BigInteger hd = params.getH().multiply(this.key.getD()).mod(params.getN());
        ECPoint pubPoint = ECAlgorithms.cleanPoint(params.getCurve(), pub.getQ());
        if (pubPoint.isInfinity()) {
            throw new IllegalStateException("Infinity is not a valid public key for ECDHC");
        }
        ECPoint P = pubPoint.multiply(hd).normalize();
        if (!P.isInfinity()) {
            return P.getAffineXCoord().toBigInteger();
        }
        throw new IllegalStateException("Infinity is not a valid agreement value for ECDHC");
    }
}
