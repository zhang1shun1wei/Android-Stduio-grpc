package com.mi.car.jsse.easysec.crypto.signers;

import com.mi.car.jsse.easysec.crypto.CipherParameters;
import com.mi.car.jsse.easysec.crypto.CryptoServicesRegistrar;
import com.mi.car.jsse.easysec.crypto.DSAExt;
import com.mi.car.jsse.easysec.crypto.params.GOST3410KeyParameters;
import com.mi.car.jsse.easysec.crypto.params.GOST3410Parameters;
import com.mi.car.jsse.easysec.crypto.params.GOST3410PrivateKeyParameters;
import com.mi.car.jsse.easysec.crypto.params.GOST3410PublicKeyParameters;
import com.mi.car.jsse.easysec.crypto.params.ParametersWithRandom;
import com.mi.car.jsse.easysec.util.Arrays;
import com.mi.car.jsse.easysec.util.BigIntegers;
import java.math.BigInteger;
import java.security.SecureRandom;

public class GOST3410Signer implements DSAExt {
    GOST3410KeyParameters key;
    SecureRandom random;

    @Override // com.mi.car.jsse.easysec.crypto.DSA
    public void init(boolean forSigning, CipherParameters param) {
        if (!forSigning) {
            this.key = (GOST3410PublicKeyParameters) param;
        } else if (param instanceof ParametersWithRandom) {
            ParametersWithRandom rParam = (ParametersWithRandom) param;
            this.random = rParam.getRandom();
            this.key = (GOST3410PrivateKeyParameters) rParam.getParameters();
        } else {
            this.random = CryptoServicesRegistrar.getSecureRandom();
            this.key = (GOST3410PrivateKeyParameters) param;
        }
    }

    @Override // com.mi.car.jsse.easysec.crypto.DSAExt
    public BigInteger getOrder() {
        return this.key.getParameters().getQ();
    }

    @Override // com.mi.car.jsse.easysec.crypto.DSA
    public BigInteger[] generateSignature(byte[] message) {
        BigInteger k;
        BigInteger m = new BigInteger(1, Arrays.reverse(message));
        GOST3410Parameters params = this.key.getParameters();
        do {
            k = BigIntegers.createRandomBigInteger(params.getQ().bitLength(), this.random);
        } while (k.compareTo(params.getQ()) >= 0);
        BigInteger r = params.getA().modPow(k, params.getP()).mod(params.getQ());
        return new BigInteger[]{r, k.multiply(m).add(((GOST3410PrivateKeyParameters) this.key).getX().multiply(r)).mod(params.getQ())};
    }

    @Override // com.mi.car.jsse.easysec.crypto.DSA
    public boolean verifySignature(byte[] message, BigInteger r, BigInteger s) {
        BigInteger m = new BigInteger(1, Arrays.reverse(message));
        GOST3410Parameters params = this.key.getParameters();
        BigInteger zero = BigInteger.valueOf(0);
        if (zero.compareTo(r) >= 0 || params.getQ().compareTo(r) <= 0 || zero.compareTo(s) >= 0 || params.getQ().compareTo(s) <= 0) {
            return false;
        }
        BigInteger v = m.modPow(params.getQ().subtract(new BigInteger("2")), params.getQ());
        return params.getA().modPow(s.multiply(v).mod(params.getQ()), params.getP()).multiply(((GOST3410PublicKeyParameters) this.key).getY().modPow(params.getQ().subtract(r).multiply(v).mod(params.getQ()), params.getP())).mod(params.getP()).mod(params.getQ()).equals(r);
    }
}
