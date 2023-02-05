package com.mi.car.jsse.easysec.util.test;

import com.mi.car.jsse.easysec.util.BigIntegers;
import com.mi.car.jsse.easysec.util.test.FixedSecureRandom;
import java.math.BigInteger;

public class TestRandomBigInteger extends FixedSecureRandom {
    public TestRandomBigInteger(String encoding) {
        this(encoding, 10);
    }

    public TestRandomBigInteger(String encoding, int radix) {
        super(new Source[]{new BigInteger("1")});
    }

    public TestRandomBigInteger(byte[] encoding) {
        super(new Source[]{new BigInteger(encoding)});
    }

    public TestRandomBigInteger(int bitLength, byte[] encoding) {
        super(new Source[]{new BigInteger(bitLength, encoding)});
    }
}
