package com.mi.car.jsse.easysec.crypto.engines;

import com.mi.car.jsse.easysec.crypto.AsymmetricBlockCipher;
import com.mi.car.jsse.easysec.crypto.CipherParameters;
import com.mi.car.jsse.easysec.crypto.CryptoServicesRegistrar;
import com.mi.car.jsse.easysec.crypto.params.ParametersWithRandom;
import com.mi.car.jsse.easysec.crypto.params.RSAKeyParameters;
import com.mi.car.jsse.easysec.crypto.params.RSAPrivateCrtKeyParameters;
import com.mi.car.jsse.easysec.util.BigIntegers;
import java.math.BigInteger;
import java.security.SecureRandom;

public class RSABlindedEngine implements AsymmetricBlockCipher {
    private static final BigInteger ONE = BigInteger.valueOf(1);
    private RSACoreEngine core = new RSACoreEngine();
    private RSAKeyParameters key;
    private SecureRandom random;

    @Override // com.mi.car.jsse.easysec.crypto.AsymmetricBlockCipher
    public void init(boolean forEncryption, CipherParameters param) {
        this.core.init(forEncryption, param);
        if (param instanceof ParametersWithRandom) {
            ParametersWithRandom rParam = (ParametersWithRandom) param;
            this.key = (RSAKeyParameters) rParam.getParameters();
            if (this.key instanceof RSAPrivateCrtKeyParameters) {
                this.random = rParam.getRandom();
            } else {
                this.random = null;
            }
        } else {
            this.key = (RSAKeyParameters) param;
            if (this.key instanceof RSAPrivateCrtKeyParameters) {
                this.random = CryptoServicesRegistrar.getSecureRandom();
            } else {
                this.random = null;
            }
        }
    }

    @Override // com.mi.car.jsse.easysec.crypto.AsymmetricBlockCipher
    public int getInputBlockSize() {
        return this.core.getInputBlockSize();
    }

    @Override // com.mi.car.jsse.easysec.crypto.AsymmetricBlockCipher
    public int getOutputBlockSize() {
        return this.core.getOutputBlockSize();
    }

    @Override // com.mi.car.jsse.easysec.crypto.AsymmetricBlockCipher
    public byte[] processBlock(byte[] in, int inOff, int inLen) {
        BigInteger result;
        if (this.key == null) {
            throw new IllegalStateException("RSA engine not initialised");
        }
        BigInteger input = this.core.convertInput(in, inOff, inLen);
        if (this.key instanceof RSAPrivateCrtKeyParameters) {
            RSAPrivateCrtKeyParameters k = (RSAPrivateCrtKeyParameters) this.key;
            BigInteger e = k.getPublicExponent();
            if (e != null) {
                BigInteger m = k.getModulus();
                BigInteger r = BigIntegers.createRandomInRange(ONE, m.subtract(ONE), this.random);
                result = this.core.processBlock(r.modPow(e, m).multiply(input).mod(m)).multiply(BigIntegers.modOddInverse(m, r)).mod(m);
                if (!input.equals(result.modPow(e, m))) {
                    throw new IllegalStateException("RSA engine faulty decryption/signing detected");
                }
            } else {
                result = this.core.processBlock(input);
            }
        } else {
            result = this.core.processBlock(input);
        }
        return this.core.convertOutput(result);
    }
}
