package com.mi.car.jsse.easysec.math.ec;

public abstract class AbstractECLookupTable implements ECLookupTable {
    @Override // com.mi.car.jsse.easysec.math.ec.ECLookupTable
    public ECPoint lookupVar(int index) {
        return lookup(index);
    }
}
