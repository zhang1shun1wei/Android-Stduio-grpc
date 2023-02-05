package com.mi.car.jsse.easysec.math.ec;

public interface ECLookupTable {
    int getSize();

    ECPoint lookup(int i);

    ECPoint lookupVar(int i);
}
