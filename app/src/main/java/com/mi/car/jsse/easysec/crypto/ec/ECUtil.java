package com.mi.car.jsse.easysec.crypto.ec;

import com.mi.car.jsse.easysec.math.ec.ECConstants;
import com.mi.car.jsse.easysec.util.BigIntegers;
import java.math.BigInteger;
import java.security.SecureRandom;

class ECUtil {
    ECUtil() {
    }

    static BigInteger generateK(BigInteger n, SecureRandom random) {
        int nBitLength = n.bitLength();
        while (true) {
            BigInteger k = BigIntegers.createRandomBigInteger(nBitLength, random);
            if (!k.equals(ECConstants.ZERO) && k.compareTo(n) < 0) {
                return k;
            }
        }
    }
}
