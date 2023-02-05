package com.mi.car.jsse.easysec.crypto.agreement;

import com.mi.car.jsse.easysec.crypto.BasicAgreement;
import com.mi.car.jsse.easysec.crypto.CipherParameters;
import com.mi.car.jsse.easysec.crypto.params.ECDomainParameters;
import com.mi.car.jsse.easysec.crypto.params.ECPrivateKeyParameters;
import com.mi.car.jsse.easysec.crypto.params.ECPublicKeyParameters;
import com.mi.car.jsse.easysec.crypto.params.MQVPrivateParameters;
import com.mi.car.jsse.easysec.crypto.params.MQVPublicParameters;
import com.mi.car.jsse.easysec.math.ec.ECAlgorithms;
import com.mi.car.jsse.easysec.math.ec.ECConstants;
import com.mi.car.jsse.easysec.math.ec.ECCurve;
import com.mi.car.jsse.easysec.math.ec.ECPoint;
import com.mi.car.jsse.easysec.util.Properties;
import java.math.BigInteger;

public class ECMQVBasicAgreement implements BasicAgreement {
    MQVPrivateParameters privParams;

    @Override // com.mi.car.jsse.easysec.crypto.BasicAgreement
    public void init(CipherParameters key) {
        this.privParams = (MQVPrivateParameters) key;
    }

    @Override // com.mi.car.jsse.easysec.crypto.BasicAgreement
    public int getFieldSize() {
        return (this.privParams.getStaticPrivateKey().getParameters().getCurve().getFieldSize() + 7) / 8;
    }

    @Override // com.mi.car.jsse.easysec.crypto.BasicAgreement
    public BigInteger calculateAgreement(CipherParameters pubKey) {
        if (Properties.isOverrideSet("com.mi.car.jsse.easysec.ec.disable_mqv")) {
            throw new IllegalStateException("ECMQV explicitly disabled");
        }
        MQVPublicParameters pubParams = (MQVPublicParameters) pubKey;
        ECPrivateKeyParameters staticPrivateKey = this.privParams.getStaticPrivateKey();
        ECDomainParameters parameters = staticPrivateKey.getParameters();
        if (!parameters.equals(pubParams.getStaticPublicKey().getParameters())) {
            throw new IllegalStateException("ECMQV public key components have wrong domain parameters");
        }
        ECPoint agreement = calculateMqvAgreement(parameters, staticPrivateKey, this.privParams.getEphemeralPrivateKey(), this.privParams.getEphemeralPublicKey(), pubParams.getStaticPublicKey(), pubParams.getEphemeralPublicKey()).normalize();
        if (!agreement.isInfinity()) {
            return agreement.getAffineXCoord().toBigInteger();
        }
        throw new IllegalStateException("Infinity is not a valid agreement value for MQV");
    }

    private ECPoint calculateMqvAgreement(ECDomainParameters parameters, ECPrivateKeyParameters d1U, ECPrivateKeyParameters d2U, ECPublicKeyParameters Q2U, ECPublicKeyParameters Q1V, ECPublicKeyParameters Q2V) {
        BigInteger n = parameters.getN();
        int e = (n.bitLength() + 1) / 2;
        BigInteger powE = ECConstants.ONE.shiftLeft(e);
        ECCurve curve = parameters.getCurve();
        ECPoint q2u = ECAlgorithms.cleanPoint(curve, Q2U.getQ());
        ECPoint q1v = ECAlgorithms.cleanPoint(curve, Q1V.getQ());
        ECPoint q2v = ECAlgorithms.cleanPoint(curve, Q2V.getQ());
        BigInteger s = d1U.getD().multiply(q2u.getAffineXCoord().toBigInteger().mod(powE).setBit(e)).add(d2U.getD()).mod(n);
        BigInteger Q2VBar = q2v.getAffineXCoord().toBigInteger().mod(powE).setBit(e);
        BigInteger hs = parameters.getH().multiply(s).mod(n);
        return ECAlgorithms.sumOfTwoMultiplies(q1v, Q2VBar.multiply(hs).mod(n), q2v, hs);
    }
}
