package com.mi.car.jsse.easysec.crypto.generators;

import com.mi.car.jsse.easysec.crypto.params.DHParameters;
import com.mi.car.jsse.easysec.math.ec.WNafUtil;
import com.mi.car.jsse.easysec.util.BigIntegers;
import java.math.BigInteger;
import java.security.SecureRandom;

/* access modifiers changed from: package-private */
public class DHKeyGeneratorHelper {
    static final DHKeyGeneratorHelper INSTANCE = new DHKeyGeneratorHelper();
    private static final BigInteger ONE = BigInteger.valueOf(1);
    private static final BigInteger TWO = BigInteger.valueOf(2);

    private DHKeyGeneratorHelper() {
    }

    /* access modifiers changed from: package-private */
    public BigInteger calculatePrivate(DHParameters dhParams, SecureRandom random) {
        BigInteger x;
        int limit = dhParams.getL();
        if (limit != 0) {
            int minWeight = limit >>> 2;
            do {
                x = BigIntegers.createRandomBigInteger(limit, random).setBit(limit - 1);
            } while (WNafUtil.getNafWeight(x) < minWeight);
        } else {
            BigInteger min = TWO;
            int m = dhParams.getM();
            if (m != 0) {
                min = ONE.shiftLeft(m - 1);
            }
            BigInteger q = dhParams.getQ();
            if (q == null) {
                q = dhParams.getP();
            }
            BigInteger max = q.subtract(TWO);
            int minWeight2 = max.bitLength() >>> 2;
            do {
                x = BigIntegers.createRandomInRange(min, max, random);
            } while (WNafUtil.getNafWeight(x) < minWeight2);
        }
        return x;
    }

    /* access modifiers changed from: package-private */
    public BigInteger calculatePublic(DHParameters dhParams, BigInteger x) {
        return dhParams.getG().modPow(x, dhParams.getP());
    }
}
