package com.mi.car.jsse.easysec.crypto.agreement;

import com.mi.car.jsse.easysec.crypto.BasicAgreement;
import com.mi.car.jsse.easysec.crypto.CipherParameters;
import com.mi.car.jsse.easysec.crypto.params.DHMQVPrivateParameters;
import com.mi.car.jsse.easysec.crypto.params.DHMQVPublicParameters;
import com.mi.car.jsse.easysec.crypto.params.DHParameters;
import com.mi.car.jsse.easysec.crypto.params.DHPrivateKeyParameters;
import com.mi.car.jsse.easysec.crypto.params.DHPublicKeyParameters;
import java.math.BigInteger;

public class MQVBasicAgreement implements BasicAgreement {
    private static final BigInteger ONE = BigInteger.valueOf(1);
    DHMQVPrivateParameters privParams;

    @Override // com.mi.car.jsse.easysec.crypto.BasicAgreement
    public void init(CipherParameters key) {
        this.privParams = (DHMQVPrivateParameters) key;
    }

    @Override // com.mi.car.jsse.easysec.crypto.BasicAgreement
    public int getFieldSize() {
        return (this.privParams.getStaticPrivateKey().getParameters().getP().bitLength() + 7) / 8;
    }

    @Override // com.mi.car.jsse.easysec.crypto.BasicAgreement
    public BigInteger calculateAgreement(CipherParameters pubKey) {
        DHMQVPublicParameters pubParams = (DHMQVPublicParameters) pubKey;
        DHPrivateKeyParameters staticPrivateKey = this.privParams.getStaticPrivateKey();
        if (!this.privParams.getStaticPrivateKey().getParameters().equals(pubParams.getStaticPublicKey().getParameters())) {
            throw new IllegalStateException("MQV public key components have wrong domain parameters");
        } else if (this.privParams.getStaticPrivateKey().getParameters().getQ() == null) {
            throw new IllegalStateException("MQV key domain parameters do not have Q set");
        } else {
            BigInteger agreement = calculateDHMQVAgreement(staticPrivateKey.getParameters(), staticPrivateKey, pubParams.getStaticPublicKey(), this.privParams.getEphemeralPrivateKey(), this.privParams.getEphemeralPublicKey(), pubParams.getEphemeralPublicKey());
            if (!agreement.equals(ONE)) {
                return agreement;
            }
            throw new IllegalStateException("1 is not a valid agreement value for MQV");
        }
    }

    private BigInteger calculateDHMQVAgreement(DHParameters parameters, DHPrivateKeyParameters xA, DHPublicKeyParameters yB, DHPrivateKeyParameters rA, DHPublicKeyParameters tA, DHPublicKeyParameters tB) {
        BigInteger q = parameters.getQ();
        BigInteger twoW = BigInteger.valueOf(2).pow((q.bitLength() + 1) / 2);
        return tB.getY().multiply(yB.getY().modPow(tB.getY().mod(twoW).add(twoW), parameters.getP())).modPow(rA.getX().add(tA.getY().mod(twoW).add(twoW).multiply(xA.getX())).mod(q), parameters.getP());
    }
}
