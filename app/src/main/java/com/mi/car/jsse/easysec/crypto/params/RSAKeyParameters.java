package com.mi.car.jsse.easysec.crypto.params;

import com.mi.car.jsse.easysec.crypto.CryptoServicesRegistrar;
import com.mi.car.jsse.easysec.math.Primes;
import com.mi.car.jsse.easysec.util.BigIntegers;
import com.mi.car.jsse.easysec.util.Properties;
import java.math.BigInteger;

public class RSAKeyParameters extends AsymmetricKeyParameter {
    private static final BigInteger ONE = BigInteger.valueOf(1);
    private static final BigInteger SMALL_PRIMES_PRODUCT = new BigInteger("8138e8a0fcf3a4e84a771d40fd305d7f4aa59306d7251de54d98af8fe95729a1f73d893fa424cd2edc8636a6c3285e022b0e3866a565ae8108eed8591cd4fe8d2ce86165a978d719ebf647f362d33fca29cd179fb42401cbaf3df0c614056f9c8f3cfd51e474afb6bc6974f78db8aba8e9e517fded658591ab7502bd41849462f", 16);
    private static final BigIntegers.Cache validated = new BigIntegers.Cache();
    private BigInteger exponent;
    private BigInteger modulus;

    public RSAKeyParameters(boolean isPrivate, BigInteger modulus2, BigInteger exponent2) {
        this(isPrivate, modulus2, exponent2, false);
    }

    public RSAKeyParameters(boolean isPrivate, BigInteger modulus2, BigInteger exponent2, boolean isInternal) {
        super(isPrivate);
        if (isPrivate || (exponent2.intValue() & 1) != 0) {
            this.modulus = !validated.contains(modulus2) ? validate(modulus2, isInternal) : modulus2;
            this.exponent = exponent2;
            return;
        }
        throw new IllegalArgumentException("RSA publicExponent is even");
    }

    private BigInteger validate(BigInteger modulus2, boolean isInternal) {
        if (isInternal) {
            validated.add(modulus2);
        } else if ((modulus2.intValue() & 1) == 0) {
            throw new IllegalArgumentException("RSA modulus is even");
        } else if (!Properties.isOverrideSet("com.mi.car.jsse.easysec.rsa.allow_unsafe_mod")) {
            if (Properties.asInteger("com.mi.car.jsse.easysec.rsa.max_size", 15360) < modulus2.bitLength()) {
                throw new IllegalArgumentException("modulus value out of range");
            } else if (!modulus2.gcd(SMALL_PRIMES_PRODUCT).equals(ONE)) {
                throw new IllegalArgumentException("RSA modulus has a small prime factor");
            } else {
                int bits = modulus2.bitLength() / 2;
                if (!Primes.enhancedMRProbablePrimeTest(modulus2, CryptoServicesRegistrar.getSecureRandom(), bits >= 1536 ? 3 : bits >= 1024 ? 4 : bits >= 512 ? 7 : 50).isProvablyComposite()) {
                    throw new IllegalArgumentException("RSA modulus is not composite");
                }
                validated.add(modulus2);
            }
        }
        return modulus2;
    }

    public BigInteger getModulus() {
        return this.modulus;
    }

    public BigInteger getExponent() {
        return this.exponent;
    }
}
