package com.mi.car.jsse.easysec.crypto.agreement;

import com.mi.car.jsse.easysec.crypto.AsymmetricCipherKeyPair;
import com.mi.car.jsse.easysec.crypto.CipherParameters;
import com.mi.car.jsse.easysec.crypto.CryptoServicesRegistrar;
import com.mi.car.jsse.easysec.crypto.generators.DHKeyPairGenerator;
import com.mi.car.jsse.easysec.crypto.params.AsymmetricKeyParameter;
import com.mi.car.jsse.easysec.crypto.params.DHKeyGenerationParameters;
import com.mi.car.jsse.easysec.crypto.params.DHParameters;
import com.mi.car.jsse.easysec.crypto.params.DHPrivateKeyParameters;
import com.mi.car.jsse.easysec.crypto.params.DHPublicKeyParameters;
import com.mi.car.jsse.easysec.crypto.params.ParametersWithRandom;
import java.math.BigInteger;
import java.security.SecureRandom;

public class DHAgreement {
    private static final BigInteger ONE = BigInteger.valueOf(1);
    private DHParameters dhParams;
    private DHPrivateKeyParameters key;
    private BigInteger privateValue;
    private SecureRandom random;

    public void init(CipherParameters param) {
        AsymmetricKeyParameter kParam;
        if (param instanceof ParametersWithRandom) {
            ParametersWithRandom rParam = (ParametersWithRandom) param;
            this.random = rParam.getRandom();
            kParam = (AsymmetricKeyParameter) rParam.getParameters();
        } else {
            this.random = CryptoServicesRegistrar.getSecureRandom();
            kParam = (AsymmetricKeyParameter) param;
        }
        if (!(kParam instanceof DHPrivateKeyParameters)) {
            throw new IllegalArgumentException("DHEngine expects DHPrivateKeyParameters");
        }
        this.key = (DHPrivateKeyParameters) kParam;
        this.dhParams = this.key.getParameters();
    }

    public BigInteger calculateMessage() {
        DHKeyPairGenerator dhGen = new DHKeyPairGenerator();
        dhGen.init(new DHKeyGenerationParameters(this.random, this.dhParams));
        AsymmetricCipherKeyPair dhPair = dhGen.generateKeyPair();
        this.privateValue = ((DHPrivateKeyParameters) dhPair.getPrivate()).getX();
        return ((DHPublicKeyParameters) dhPair.getPublic()).getY();
    }

    public BigInteger calculateAgreement(DHPublicKeyParameters pub, BigInteger message) {
        if (!pub.getParameters().equals(this.dhParams)) {
            throw new IllegalArgumentException("Diffie-Hellman public key has wrong parameters.");
        }
        BigInteger p = this.dhParams.getP();
        BigInteger peerY = pub.getY();
        if (peerY == null || peerY.compareTo(ONE) <= 0 || peerY.compareTo(p.subtract(ONE)) >= 0) {
            throw new IllegalArgumentException("Diffie-Hellman public key is weak");
        }
        BigInteger result = peerY.modPow(this.privateValue, p);
        if (!result.equals(ONE)) {
            return message.modPow(this.key.getX(), p).multiply(result).mod(p);
        }
        throw new IllegalStateException("Shared key can't be 1");
    }
}
