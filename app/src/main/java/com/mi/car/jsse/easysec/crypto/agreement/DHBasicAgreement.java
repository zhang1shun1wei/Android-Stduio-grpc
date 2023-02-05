package com.mi.car.jsse.easysec.crypto.agreement;

import com.mi.car.jsse.easysec.crypto.BasicAgreement;
import com.mi.car.jsse.easysec.crypto.CipherParameters;
import com.mi.car.jsse.easysec.crypto.params.AsymmetricKeyParameter;
import com.mi.car.jsse.easysec.crypto.params.DHParameters;
import com.mi.car.jsse.easysec.crypto.params.DHPrivateKeyParameters;
import com.mi.car.jsse.easysec.crypto.params.DHPublicKeyParameters;
import com.mi.car.jsse.easysec.crypto.params.ParametersWithRandom;
import java.math.BigInteger;

public class DHBasicAgreement implements BasicAgreement {
    private static final BigInteger ONE = BigInteger.valueOf(1);
    private DHParameters dhParams;
    private DHPrivateKeyParameters key;

    @Override // com.mi.car.jsse.easysec.crypto.BasicAgreement
    public void init(CipherParameters param) {
        AsymmetricKeyParameter kParam;
        if (param instanceof ParametersWithRandom) {
            kParam = (AsymmetricKeyParameter) ((ParametersWithRandom) param).getParameters();
        } else {
            kParam = (AsymmetricKeyParameter) param;
        }
        if (!(kParam instanceof DHPrivateKeyParameters)) {
            throw new IllegalArgumentException("DHEngine expects DHPrivateKeyParameters");
        }
        this.key = (DHPrivateKeyParameters) kParam;
        this.dhParams = this.key.getParameters();
    }

    @Override // com.mi.car.jsse.easysec.crypto.BasicAgreement
    public int getFieldSize() {
        return (this.key.getParameters().getP().bitLength() + 7) / 8;
    }

    @Override // com.mi.car.jsse.easysec.crypto.BasicAgreement
    public BigInteger calculateAgreement(CipherParameters pubKey) {
        DHPublicKeyParameters pub = (DHPublicKeyParameters) pubKey;
        if (!pub.getParameters().equals(this.dhParams)) {
            throw new IllegalArgumentException("Diffie-Hellman public key has wrong parameters.");
        }
        BigInteger p = this.dhParams.getP();
        BigInteger peerY = pub.getY();
        if (peerY == null || peerY.compareTo(ONE) <= 0 || peerY.compareTo(p.subtract(ONE)) >= 0) {
            throw new IllegalArgumentException("Diffie-Hellman public key is weak");
        }
        BigInteger result = peerY.modPow(this.key.getX(), p);
        if (!result.equals(ONE)) {
            return result;
        }
        throw new IllegalStateException("Shared key can't be 1");
    }
}
