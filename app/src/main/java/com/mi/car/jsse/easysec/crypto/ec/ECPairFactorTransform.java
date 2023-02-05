package com.mi.car.jsse.easysec.crypto.ec;

import java.math.BigInteger;

public interface ECPairFactorTransform extends ECPairTransform {
    BigInteger getTransformValue();
}
