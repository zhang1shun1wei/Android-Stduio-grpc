package com.mi.car.jsse.easysec.crypto.signers;

import com.mi.car.jsse.easysec.util.BigIntegers;
import java.math.BigInteger;
import java.security.SecureRandom;

public class RandomDSAKCalculator implements DSAKCalculator {
    private static final BigInteger ZERO = BigInteger.valueOf(0);
    private BigInteger q;
    private SecureRandom random;

    @Override // com.mi.car.jsse.easysec.crypto.signers.DSAKCalculator
    public boolean isDeterministic() {
        return false;
    }

    @Override // com.mi.car.jsse.easysec.crypto.signers.DSAKCalculator
    public void init(BigInteger n, SecureRandom random2) {
        this.q = n;
        this.random = random2;
    }

    @Override // com.mi.car.jsse.easysec.crypto.signers.DSAKCalculator
    public void init(BigInteger n, BigInteger d, byte[] message) {
        throw new IllegalStateException("Operation not supported");
    }

    @Override // com.mi.car.jsse.easysec.crypto.signers.DSAKCalculator
    public BigInteger nextK() {
        int qBitLength = this.q.bitLength();
        while (true) {
            BigInteger k = BigIntegers.createRandomBigInteger(qBitLength, this.random);
            if (!k.equals(ZERO) && k.compareTo(this.q) < 0) {
                return k;
            }
        }
    }
}
