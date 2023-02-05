package com.mi.car.jsse.easysec.crypto.params;

import com.mi.car.jsse.easysec.util.Arrays;

public class DHValidationParameters {
    private int counter;
    private byte[] seed;

    public DHValidationParameters(byte[] seed2, int counter2) {
        this.seed = Arrays.clone(seed2);
        this.counter = counter2;
    }

    public int getCounter() {
        return this.counter;
    }

    public byte[] getSeed() {
        return Arrays.clone(this.seed);
    }

    public boolean equals(Object o) {
        if (!(o instanceof DHValidationParameters)) {
            return false;
        }
        DHValidationParameters other = (DHValidationParameters) o;
        if (other.counter == this.counter) {
            return Arrays.areEqual(this.seed, other.seed);
        }
        return false;
    }

    public int hashCode() {
        return this.counter ^ Arrays.hashCode(this.seed);
    }
}
