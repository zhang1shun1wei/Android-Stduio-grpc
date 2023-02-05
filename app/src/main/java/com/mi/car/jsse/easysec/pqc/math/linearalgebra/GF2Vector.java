package com.mi.car.jsse.easysec.pqc.math.linearalgebra;

import com.mi.car.jsse.easysec.util.Arrays;
import java.security.SecureRandom;

public class GF2Vector extends Vector {
    private int[] v;

    public GF2Vector(int length) {
        if (length < 0) {
            throw new ArithmeticException("Negative length.");
        }
        this.length = length;
        this.v = new int[((length + 31) >> 5)];
    }

    public GF2Vector(int length, SecureRandom sr) {
        this.length = length;
        int size = (length + 31) >> 5;
        this.v = new int[size];
        for (int i = size - 1; i >= 0; i--) {
            this.v[i] = sr.nextInt();
        }
        int r = length & 31;
        if (r != 0) {
            int[] iArr = this.v;
            int i2 = size - 1;
            iArr[i2] = iArr[i2] & ((1 << r) - 1);
        }
    }

    public GF2Vector(int length, int t, SecureRandom sr) {
        if (t > length) {
            throw new ArithmeticException("The hamming weight is greater than the length of vector.");
        }
        this.length = length;
        this.v = new int[((length + 31) >> 5)];
        int[] help = new int[length];
        for (int i = 0; i < length; i++) {
            help[i] = i;
        }
        int m = length;
        for (int i2 = 0; i2 < t; i2++) {
            int j = RandUtils.nextInt(sr, m);
            setBit(help[j]);
            m--;
            help[j] = help[m];
        }
    }

    public GF2Vector(int length, int[] v2) {
        if (length < 0) {
            throw new ArithmeticException("negative length");
        }
        this.length = length;
        int size = (length + 31) >> 5;
        if (v2.length != size) {
            throw new ArithmeticException("length mismatch");
        }
        this.v = IntUtils.clone(v2);
        int r = length & 31;
        if (r != 0) {
            int[] iArr = this.v;
            int i = size - 1;
            iArr[i] = iArr[i] & ((1 << r) - 1);
        }
    }

    public GF2Vector(GF2Vector other) {
        this.length = other.length;
        this.v = IntUtils.clone(other.v);
    }

    protected GF2Vector(int[] v2, int length) {
        this.v = v2;
        this.length = length;
    }

    public static GF2Vector OS2VP(int length, byte[] encVec) {
        if (length < 0) {
            throw new ArithmeticException("negative length");
        }
        if (encVec.length <= ((length + 7) >> 3)) {
            return new GF2Vector(length, LittleEndianConversions.toIntArray(encVec));
        }
        throw new ArithmeticException("length mismatch");
    }

    @Override // com.mi.car.jsse.easysec.pqc.math.linearalgebra.Vector
    public byte[] getEncoded() {
        return LittleEndianConversions.toByteArray(this.v, (this.length + 7) >> 3);
    }

    public int[] getVecArray() {
        return this.v;
    }

    public int getHammingWeight() {
        int weight = 0;
        for (int i = 0; i < this.v.length; i++) {
            int e = this.v[i];
            for (int j = 0; j < 32; j++) {
                if ((e & 1) != 0) {
                    weight++;
                }
                e >>>= 1;
            }
        }
        return weight;
    }

    @Override // com.mi.car.jsse.easysec.pqc.math.linearalgebra.Vector
    public boolean isZero() {
        for (int i = this.v.length - 1; i >= 0; i--) {
            if (this.v[i] != 0) {
                return false;
            }
        }
        return true;
    }

    public int getBit(int index) {
        if (index >= this.length) {
            throw new IndexOutOfBoundsException();
        }
        int r = index & 31;
        return (this.v[index >> 5] & (1 << r)) >>> r;
    }

    public void setBit(int index) {
        if (index >= this.length) {
            throw new IndexOutOfBoundsException();
        }
        int[] iArr = this.v;
        int i = index >> 5;
        iArr[i] = iArr[i] | (1 << (index & 31));
    }

    @Override // com.mi.car.jsse.easysec.pqc.math.linearalgebra.Vector
    public Vector add(Vector other) {
        if (!(other instanceof GF2Vector)) {
            throw new ArithmeticException("vector is not defined over GF(2)");
        } else if (this.length != ((GF2Vector) other).length) {
            throw new ArithmeticException("length mismatch");
        } else {
            int[] vec = IntUtils.clone(((GF2Vector) other).v);
            for (int i = vec.length - 1; i >= 0; i--) {
                vec[i] = vec[i] ^ this.v[i];
            }
            return new GF2Vector(this.length, vec);
        }
    }

    @Override // com.mi.car.jsse.easysec.pqc.math.linearalgebra.Vector
    public Vector multiply(Permutation p) {
        int[] pVec = p.getVector();
        if (this.length != pVec.length) {
            throw new ArithmeticException("length mismatch");
        }
        GF2Vector result = new GF2Vector(this.length);
        for (int i = 0; i < pVec.length; i++) {
            if ((this.v[pVec[i] >> 5] & (1 << (pVec[i] & 31))) != 0) {
                int[] iArr = result.v;
                int i2 = i >> 5;
                iArr[i2] = iArr[i2] | (1 << (i & 31));
            }
        }
        return result;
    }

    public GF2Vector extractVector(int[] setJ) {
        int k = setJ.length;
        if (setJ[k - 1] > this.length) {
            throw new ArithmeticException("invalid index set");
        }
        GF2Vector result = new GF2Vector(k);
        for (int i = 0; i < k; i++) {
            if ((this.v[setJ[i] >> 5] & (1 << (setJ[i] & 31))) != 0) {
                int[] iArr = result.v;
                int i2 = i >> 5;
                iArr[i2] = iArr[i2] | (1 << (i & 31));
            }
        }
        return result;
    }

    public GF2Vector extractLeftVector(int k) {
        if (k > this.length) {
            throw new ArithmeticException("invalid length");
        } else if (k == this.length) {
            return new GF2Vector(this);
        } else {
            GF2Vector result = new GF2Vector(k);
            int q = k >> 5;
            int r = k & 31;
            System.arraycopy(this.v, 0, result.v, 0, q);
            if (r == 0) {
                return result;
            }
            result.v[q] = this.v[q] & ((1 << r) - 1);
            return result;
        }
    }

    public GF2Vector extractRightVector(int k) {
        if (k > this.length) {
            throw new ArithmeticException("invalid length");
        } else if (k == this.length) {
            return new GF2Vector(this);
        } else {
            GF2Vector result = new GF2Vector(k);
            int q = (this.length - k) >> 5;
            int r = (this.length - k) & 31;
            int length = (k + 31) >> 5;
            int ind = q;
            if (r != 0) {
                for (int i = 0; i < length - 1; i++) {
                    ind++;
                    result.v[i] = (this.v[ind] >>> r) | (this.v[ind] << (32 - r));
                }
                int ind2 = ind + 1;
                result.v[length - 1] = this.v[ind] >>> r;
                if (ind2 >= this.v.length) {
                    return result;
                }
                int[] iArr = result.v;
                int i2 = length - 1;
                iArr[i2] = iArr[i2] | (this.v[ind2] << (32 - r));
                return result;
            }
            System.arraycopy(this.v, q, result.v, 0, length);
            return result;
        }
    }

    public GF2mVector toExtensionFieldVector(GF2mField field) {
        int m = field.getDegree();
        if (this.length % m != 0) {
            throw new ArithmeticException("conversion is impossible");
        }
        int t = this.length / m;
        int[] result = new int[t];
        int count = 0;
        for (int i = t - 1; i >= 0; i--) {
            for (int j = field.getDegree() - 1; j >= 0; j--) {
                if (((this.v[count >>> 5] >>> (count & 31)) & 1) == 1) {
                    result[i] = result[i] ^ (1 << j);
                }
                count++;
            }
        }
        return new GF2mVector(field, result);
    }

    @Override // com.mi.car.jsse.easysec.pqc.math.linearalgebra.Vector
    public boolean equals(Object other) {
        if (!(other instanceof GF2Vector)) {
            return false;
        }
        GF2Vector otherVec = (GF2Vector) other;
        if (this.length != otherVec.length || !IntUtils.equals(this.v, otherVec.v)) {
            return false;
        }
        return true;
    }

    @Override // com.mi.car.jsse.easysec.pqc.math.linearalgebra.Vector
    public int hashCode() {
        return (this.length * 31) + Arrays.hashCode(this.v);
    }

    @Override // com.mi.car.jsse.easysec.pqc.math.linearalgebra.Vector
    public String toString() {
        StringBuffer buf = new StringBuffer();
        for (int i = 0; i < this.length; i++) {
            if (i != 0 && (i & 31) == 0) {
                buf.append(' ');
            }
            if ((this.v[i >> 5] & (1 << (i & 31))) == 0) {
                buf.append('0');
            } else {
                buf.append('1');
            }
        }
        return buf.toString();
    }
}
