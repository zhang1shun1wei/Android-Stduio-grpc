package com.mi.car.jsse.easysec.math.field;

import java.math.BigInteger;

/* access modifiers changed from: package-private */
public class PrimeField implements FiniteField {
    protected final BigInteger characteristic;

    PrimeField(BigInteger characteristic2) {
        this.characteristic = characteristic2;
    }

    @Override // com.mi.car.jsse.easysec.math.field.FiniteField
    public BigInteger getCharacteristic() {
        return this.characteristic;
    }

    @Override // com.mi.car.jsse.easysec.math.field.FiniteField
    public int getDimension() {
        return 1;
    }

    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof PrimeField)) {
            return false;
        }
        return this.characteristic.equals(((PrimeField) obj).characteristic);
    }

    public int hashCode() {
        return this.characteristic.hashCode();
    }
}
