package com.mi.car.jsse.easysec.crypto.params;

public class GOST3410ValidationParameters {
    private int c;
    private long cL;
    private int x0;
    private long x0L;

    public GOST3410ValidationParameters(int x02, int c2) {
        this.x0 = x02;
        this.c = c2;
    }

    public GOST3410ValidationParameters(long x0L2, long cL2) {
        this.x0L = x0L2;
        this.cL = cL2;
    }

    public int getC() {
        return this.c;
    }

    public int getX0() {
        return this.x0;
    }

    public long getCL() {
        return this.cL;
    }

    public long getX0L() {
        return this.x0L;
    }

    public boolean equals(Object o) {
        if (!(o instanceof GOST3410ValidationParameters)) {
            return false;
        }
        GOST3410ValidationParameters other = (GOST3410ValidationParameters) o;
        if (other.c == this.c && other.x0 == this.x0 && other.cL == this.cL && other.x0L == this.x0L) {
            return true;
        }
        return false;
    }

    public int hashCode() {
        return ((((this.x0 ^ this.c) ^ ((int) this.x0L)) ^ ((int) (this.x0L >> 32))) ^ ((int) this.cL)) ^ ((int) (this.cL >> 32));
    }
}
