package com.mi.car.jsse.easysec.crypto.ec;

import com.mi.car.jsse.easysec.math.ec.ECPoint;

public class ECPair {
    private final ECPoint x;
    private final ECPoint y;

    public ECPair(ECPoint x2, ECPoint y2) {
        this.x = x2;
        this.y = y2;
    }

    public ECPoint getX() {
        return this.x;
    }

    public ECPoint getY() {
        return this.y;
    }

    public boolean equals(ECPair other) {
        return other.getX().equals(getX()) && other.getY().equals(getY());
    }

    public boolean equals(Object other) {
        if (other instanceof ECPair) {
            return equals((ECPair) other);
        }
        return false;
    }

    public int hashCode() {
        return this.x.hashCode() + (this.y.hashCode() * 37);
    }
}
