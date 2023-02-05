package com.mi.car.jsse.easysec.pqc.math.linearalgebra;

import com.mi.car.jsse.easysec.util.Arrays;

public class GF2mVector extends Vector {
    private GF2mField field;
    private int[] vector;

    public GF2mVector(GF2mField field2, byte[] v) {
        this.field = new GF2mField(field2);
        int d = 8;
        int count = 1;
        while (field2.getDegree() > d) {
            count++;
            d += 8;
        }
        if (v.length % count != 0) {
            throw new IllegalArgumentException("Byte array is not an encoded vector over the given finite field.");
        }
        this.length = v.length / count;
        this.vector = new int[this.length];
        int count2 = 0;
        int i = 0;
        while (i < this.vector.length) {
            int j = 0;
            int count3 = count2;
            while (j < d) {
                int[] iArr = this.vector;
                iArr[i] = iArr[i] | ((v[count3] & 255) << j);
                j += 8;
                count3++;
            }
            if (!field2.isElementOfThisField(this.vector[i])) {
                throw new IllegalArgumentException("Byte array is not an encoded vector over the given finite field.");
            }
            i++;
            count2 = count3;
        }
    }

    public GF2mVector(GF2mField field2, int[] vector2) {
        this.field = field2;
        this.length = vector2.length;
        for (int i = vector2.length - 1; i >= 0; i--) {
            if (!field2.isElementOfThisField(vector2[i])) {
                throw new ArithmeticException("Element array is not specified over the given finite field.");
            }
        }
        this.vector = IntUtils.clone(vector2);
    }

    public GF2mVector(GF2mVector other) {
        this.field = new GF2mField(other.field);
        this.length = other.length;
        this.vector = IntUtils.clone(other.vector);
    }

    public GF2mField getField() {
        return this.field;
    }

    public int[] getIntArrayForm() {
        return IntUtils.clone(this.vector);
    }

    @Override // com.mi.car.jsse.easysec.pqc.math.linearalgebra.Vector
    public byte[] getEncoded() {
        int d = 8;
        int count = 1;
        while (this.field.getDegree() > d) {
            count++;
            d += 8;
        }
        byte[] res = new byte[(this.vector.length * count)];
        int count2 = 0;
        int i = 0;
        while (i < this.vector.length) {
            int j = 0;
            int count3 = count2;
            while (j < d) {
                res[count3] = (byte) (this.vector[i] >>> j);
                j += 8;
                count3++;
            }
            i++;
            count2 = count3;
        }
        return res;
    }

    @Override // com.mi.car.jsse.easysec.pqc.math.linearalgebra.Vector
    public boolean isZero() {
        for (int i = this.vector.length - 1; i >= 0; i--) {
            if (this.vector[i] != 0) {
                return false;
            }
        }
        return true;
    }

    @Override // com.mi.car.jsse.easysec.pqc.math.linearalgebra.Vector
    public Vector add(Vector addend) {
        throw new RuntimeException("not implemented");
    }

    @Override // com.mi.car.jsse.easysec.pqc.math.linearalgebra.Vector
    public Vector multiply(Permutation p) {
        int[] pVec = p.getVector();
        if (this.length != pVec.length) {
            throw new ArithmeticException("permutation size and vector size mismatch");
        }
        int[] result = new int[this.length];
        for (int i = 0; i < pVec.length; i++) {
            result[i] = this.vector[pVec[i]];
        }
        return new GF2mVector(this.field, result);
    }

    @Override // com.mi.car.jsse.easysec.pqc.math.linearalgebra.Vector
    public boolean equals(Object other) {
        if (!(other instanceof GF2mVector)) {
            return false;
        }
        GF2mVector otherVec = (GF2mVector) other;
        if (this.field.equals(otherVec.field)) {
            return IntUtils.equals(this.vector, otherVec.vector);
        }
        return false;
    }

    @Override // com.mi.car.jsse.easysec.pqc.math.linearalgebra.Vector
    public int hashCode() {
        return (this.field.hashCode() * 31) + Arrays.hashCode(this.vector);
    }

    @Override // com.mi.car.jsse.easysec.pqc.math.linearalgebra.Vector
    public String toString() {
        StringBuffer buf = new StringBuffer();
        for (int i = 0; i < this.vector.length; i++) {
            for (int j = 0; j < this.field.getDegree(); j++) {
                if ((this.vector[i] & (1 << (j & 31))) != 0) {
                    buf.append('1');
                } else {
                    buf.append('0');
                }
            }
            buf.append(' ');
        }
        return buf.toString();
    }
}
