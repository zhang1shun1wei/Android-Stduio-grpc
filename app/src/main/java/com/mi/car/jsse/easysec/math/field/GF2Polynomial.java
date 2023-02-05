package com.mi.car.jsse.easysec.math.field;

import com.mi.car.jsse.easysec.util.Arrays;

/* access modifiers changed from: package-private */
public class GF2Polynomial implements Polynomial {
    protected final int[] exponents;

    GF2Polynomial(int[] exponents2) {
        this.exponents = Arrays.clone(exponents2);
    }

    @Override // com.mi.car.jsse.easysec.math.field.Polynomial
    public int getDegree() {
        return this.exponents[this.exponents.length - 1];
    }

    @Override // com.mi.car.jsse.easysec.math.field.Polynomial
    public int[] getExponentsPresent() {
        return Arrays.clone(this.exponents);
    }

    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof GF2Polynomial)) {
            return false;
        }
        return Arrays.areEqual(this.exponents, ((GF2Polynomial) obj).exponents);
    }

    public int hashCode() {
        return Arrays.hashCode(this.exponents);
    }
}
