package com.mi.car.jsse.easysec.math.field;

import java.math.BigInteger;

public interface FiniteField {
    BigInteger getCharacteristic();

    int getDimension();
}
