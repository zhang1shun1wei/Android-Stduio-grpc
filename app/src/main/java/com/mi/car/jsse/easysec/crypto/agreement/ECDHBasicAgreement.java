package com.mi.car.jsse.easysec.crypto.agreement;

import com.mi.car.jsse.easysec.crypto.BasicAgreement;
import com.mi.car.jsse.easysec.crypto.CipherParameters;
import com.mi.car.jsse.easysec.crypto.params.ECDomainParameters;
import com.mi.car.jsse.easysec.crypto.params.ECPrivateKeyParameters;
import com.mi.car.jsse.easysec.crypto.params.ECPublicKeyParameters;
import com.mi.car.jsse.easysec.math.ec.ECAlgorithms;
import com.mi.car.jsse.easysec.math.ec.ECConstants;
import com.mi.car.jsse.easysec.math.ec.ECPoint;
import java.math.BigInteger;

public class ECDHBasicAgreement implements BasicAgreement {
    private ECPrivateKeyParameters key;

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
            throw new IllegalStateException("ECDH public key has wrong domain parameters");
        }
        BigInteger d = this.key.getD();
        ECPoint Q = ECAlgorithms.cleanPoint(params.getCurve(), pub.getQ());
        if (Q.isInfinity()) {
            throw new IllegalStateException("Infinity is not a valid public key for ECDH");
        }
        BigInteger h = params.getH();
        if (!h.equals(ECConstants.ONE)) {
            d = params.getHInv().multiply(d).mod(params.getN());
            Q = ECAlgorithms.referenceMultiply(Q, h);
        }
        ECPoint P = Q.multiply(d).normalize();
        if (!P.isInfinity()) {
            return P.getAffineXCoord().toBigInteger();
        }
        throw new IllegalStateException("Infinity is not a valid agreement value for ECDH");
    }
}
