package com.mi.car.jsse.easysec.crypto.generators;

import com.mi.car.jsse.easysec.crypto.AsymmetricCipherKeyPair;
import com.mi.car.jsse.easysec.crypto.AsymmetricCipherKeyPairGenerator;
import com.mi.car.jsse.easysec.crypto.KeyGenerationParameters;
import com.mi.car.jsse.easysec.crypto.params.AsymmetricKeyParameter;
import com.mi.car.jsse.easysec.crypto.params.RSAKeyGenerationParameters;
import com.mi.car.jsse.easysec.crypto.params.RSAKeyParameters;
import com.mi.car.jsse.easysec.crypto.params.RSAPrivateCrtKeyParameters;
import com.mi.car.jsse.easysec.math.Primes;
import com.mi.car.jsse.easysec.math.ec.WNafUtil;
import com.mi.car.jsse.easysec.util.BigIntegers;
import java.math.BigInteger;

public class RSAKeyPairGenerator implements AsymmetricCipherKeyPairGenerator {
    private static final BigInteger ONE = BigInteger.valueOf(1);
    private RSAKeyGenerationParameters param;

    @Override // com.mi.car.jsse.easysec.crypto.AsymmetricCipherKeyPairGenerator
    public void init(KeyGenerationParameters param2) {
        this.param = (RSAKeyGenerationParameters) param2;
    }

    @Override // com.mi.car.jsse.easysec.crypto.AsymmetricCipherKeyPairGenerator
    public AsymmetricCipherKeyPair generateKeyPair() {
        BigInteger q;
        BigInteger n;
        AsymmetricCipherKeyPair result = null;
        boolean done = false;
        int strength = this.param.getStrength();
        int pbitlength = (strength + 1) / 2;
        int qbitlength = strength - pbitlength;
        int mindiffbits = (strength / 2) - 100;
        if (mindiffbits < strength / 3) {
            mindiffbits = strength / 3;
        }
        int minWeight = strength >> 2;
        BigInteger dLowerBound = BigInteger.valueOf(2).pow(strength / 2);
        BigInteger squaredBound = ONE.shiftLeft(strength - 1);
        BigInteger minDiff = ONE.shiftLeft(mindiffbits);
        while (!done) {
            BigInteger e = this.param.getPublicExponent();
            BigInteger p = chooseRandomPrime(pbitlength, e, squaredBound);
            while (true) {
                q = chooseRandomPrime(qbitlength, e, squaredBound);
                BigInteger diff = q.subtract(p).abs();
                if (diff.bitLength() >= mindiffbits && diff.compareTo(minDiff) > 0) {
                    n = p.multiply(q);
                    if (n.bitLength() == strength) {
                        if (WNafUtil.getNafWeight(n) >= minWeight) {
                            break;
                        }
                        p = chooseRandomPrime(pbitlength, e, squaredBound);
                    } else {
                        p = p.max(q);
                    }
                }
            }
            if (p.compareTo(q) < 0) {
                p = q;
                q = p;
            }
            BigInteger pSub1 = p.subtract(ONE);
            BigInteger qSub1 = q.subtract(ONE);
            BigInteger d = e.modInverse(pSub1.divide(pSub1.gcd(qSub1)).multiply(qSub1));
            if (d.compareTo(dLowerBound) > 0) {
                done = true;
                result = new AsymmetricCipherKeyPair((AsymmetricKeyParameter) new RSAKeyParameters(false, n, e, true), (AsymmetricKeyParameter) new RSAPrivateCrtKeyParameters(n, e, d, p, q, d.remainder(pSub1), d.remainder(qSub1), BigIntegers.modOddInverse(p, q), true));
            }
        }
        return result;
    }

    /* access modifiers changed from: protected */
    public BigInteger chooseRandomPrime(int bitlength, BigInteger e, BigInteger sqrdBound) {
        for (int i = 0; i != bitlength * 5; i++) {
            BigInteger p = BigIntegers.createRandomPrime(bitlength, 1, this.param.getRandom());
            if (!p.mod(e).equals(ONE) && p.multiply(p).compareTo(sqrdBound) >= 0 && isProbablePrime(p) && e.gcd(p.subtract(ONE)).equals(ONE)) {
                return p;
            }
        }
        throw new IllegalStateException("unable to generate prime number for RSA key");
    }

    /* access modifiers changed from: protected */
    public boolean isProbablePrime(BigInteger x) {
        return !Primes.hasAnySmallFactors(x) && Primes.isMRProbablePrime(x, this.param.getRandom(), getNumberOfIterations(x.bitLength(), this.param.getCertainty()));
    }

    private static int getNumberOfIterations(int bits, int certainty) {
        int i = 5;
        if (bits >= 1536) {
            if (certainty <= 100) {
                return 3;
            }
            if (certainty > 128) {
                return (((certainty - 128) + 1) / 2) + 4;
            }
            return 4;
        } else if (bits >= 1024) {
            if (certainty <= 100) {
                return 4;
            }
            if (certainty <= 112) {
                return 5;
            }
            return (((certainty - 112) + 1) / 2) + 5;
        } else if (bits >= 512) {
            if (certainty > 80) {
                i = certainty <= 100 ? 7 : (((certainty - 100) + 1) / 2) + 7;
            }
            return i;
        } else if (certainty <= 80) {
            return 40;
        } else {
            return (((certainty - 80) + 1) / 2) + 40;
        }
    }
}
