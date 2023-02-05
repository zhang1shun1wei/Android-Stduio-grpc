package com.mi.car.jsse.easysec.pqc.math.linearalgebra;

import com.mi.car.jsse.easysec.util.Arrays;
import java.math.BigInteger;
import java.security.SecureRandom;

public class GF2nONBElement extends GF2nElement {
    private static final int MAXLONG = 64;
    private static final long[] mBitmask = {1, 2, 4, 8, 16, 32, 64, 128, 256, 512, 1024, 2048, 4096, 8192, 16384, 32768, 65536, 131072, 262144, 524288, 1048576, 2097152, 4194304, 8388608, 16777216, 33554432, 67108864, 134217728, 268435456, 536870912, 1073741824, 2147483648L, 4294967296L, 8589934592L, 17179869184L, 34359738368L, 68719476736L, 137438953472L, 274877906944L, 549755813888L, 1099511627776L, 2199023255552L, 4398046511104L, 8796093022208L, 17592186044416L, 35184372088832L, 70368744177664L, 140737488355328L, 281474976710656L, 562949953421312L, 1125899906842624L, 2251799813685248L, 4503599627370496L, 9007199254740992L, 18014398509481984L, 36028797018963968L, 72057594037927936L, 144115188075855872L, 288230376151711744L, 576460752303423488L, 1152921504606846976L, 2305843009213693952L, 4611686018427387904L, Long.MIN_VALUE};
    private static final int[] mIBY64 = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5};
    private static final long[] mMaxmask = {1, 3, 7, 15, 31, 63, 127, 255, 511, 1023, 2047, 4095, 8191, 16383, 32767, 65535, 131071, 262143, 524287, 1048575, 2097151, 4194303, 8388607, 16777215, 33554431, 67108863, 134217727, 268435455, 536870911, 1073741823, 2147483647L, 4294967295L, 8589934591L, 17179869183L, 34359738367L, 68719476735L, 137438953471L, 274877906943L, 549755813887L, 1099511627775L, 2199023255551L, 4398046511103L, 8796093022207L, 17592186044415L, 35184372088831L, 70368744177663L, 140737488355327L, 281474976710655L, 562949953421311L, 1125899906842623L, 2251799813685247L, 4503599627370495L, 9007199254740991L, 18014398509481983L, 36028797018963967L, 72057594037927935L, 144115188075855871L, 288230376151711743L, 576460752303423487L, 1152921504606846975L, 2305843009213693951L, 4611686018427387903L, Long.MAX_VALUE, -1};
    private int mBit;
    private int mLength;
    private long[] mPol;

    public GF2nONBElement(GF2nONBField gf2n, SecureRandom rand) {
        this.mField = gf2n;
        this.mDegree = this.mField.getDegree();
        this.mLength = gf2n.getONBLength();
        this.mBit = gf2n.getONBBit();
        this.mPol = new long[this.mLength];
        if (this.mLength > 1) {
            for (int j = 0; j < this.mLength - 1; j++) {
                this.mPol[j] = rand.nextLong();
            }
            this.mPol[this.mLength - 1] = rand.nextLong() >>> (64 - this.mBit);
            return;
        }
        this.mPol[0] = rand.nextLong();
        this.mPol[0] = this.mPol[0] >>> (64 - this.mBit);
    }

    public GF2nONBElement(GF2nONBField gf2n, byte[] e) {
        this.mField = gf2n;
        this.mDegree = this.mField.getDegree();
        this.mLength = gf2n.getONBLength();
        this.mBit = gf2n.getONBBit();
        this.mPol = new long[this.mLength];
        assign(e);
    }

    public GF2nONBElement(GF2nONBField gf2n, BigInteger val) {
        this.mField = gf2n;
        this.mDegree = this.mField.getDegree();
        this.mLength = gf2n.getONBLength();
        this.mBit = gf2n.getONBBit();
        this.mPol = new long[this.mLength];
        assign(val);
    }

    private GF2nONBElement(GF2nONBField gf2n, long[] val) {
        this.mField = gf2n;
        this.mDegree = this.mField.getDegree();
        this.mLength = gf2n.getONBLength();
        this.mBit = gf2n.getONBBit();
        this.mPol = val;
    }

    public GF2nONBElement(GF2nONBElement gf2n) {
        this.mField = gf2n.mField;
        this.mDegree = this.mField.getDegree();
        this.mLength = ((GF2nONBField) this.mField).getONBLength();
        this.mBit = ((GF2nONBField) this.mField).getONBBit();
        this.mPol = new long[this.mLength];
        assign(gf2n.getElement());
    }

    @Override // com.mi.car.jsse.easysec.pqc.math.linearalgebra.GF2nElement, com.mi.car.jsse.easysec.pqc.math.linearalgebra.GFElement
    public Object clone() {
        return new GF2nONBElement(this);
    }

    public static GF2nONBElement ZERO(GF2nONBField gf2n) {
        return new GF2nONBElement(gf2n, new long[gf2n.getONBLength()]);
    }

    public static GF2nONBElement ONE(GF2nONBField gf2n) {
        int mLength2 = gf2n.getONBLength();
        long[] polynomial = new long[mLength2];
        for (int i = 0; i < mLength2 - 1; i++) {
            polynomial[i] = -1;
        }
        polynomial[mLength2 - 1] = mMaxmask[gf2n.getONBBit() - 1];
        return new GF2nONBElement(gf2n, polynomial);
    }

    /* access modifiers changed from: package-private */
    @Override // com.mi.car.jsse.easysec.pqc.math.linearalgebra.GF2nElement
    public void assignZero() {
        this.mPol = new long[this.mLength];
    }

    /* access modifiers changed from: package-private */
    @Override // com.mi.car.jsse.easysec.pqc.math.linearalgebra.GF2nElement
    public void assignOne() {
        for (int i = 0; i < this.mLength - 1; i++) {
            this.mPol[i] = -1;
        }
        this.mPol[this.mLength - 1] = mMaxmask[this.mBit - 1];
    }

    private void assign(BigInteger val) {
        assign(val.toByteArray());
    }

    private void assign(long[] val) {
        System.arraycopy(val, 0, this.mPol, 0, this.mLength);
    }

    private void assign(byte[] val) {
        this.mPol = new long[this.mLength];
        for (int j = 0; j < val.length; j++) {
            long[] jArr = this.mPol;
            int i = j >>> 3;
            jArr[i] = jArr[i] | ((((long) val[(val.length - 1) - j]) & 255) << ((j & 7) << 3));
        }
    }

    @Override // com.mi.car.jsse.easysec.pqc.math.linearalgebra.GFElement
    public boolean isZero() {
        boolean result = true;
        for (int i = 0; i < this.mLength && result; i++) {
            result = result && (this.mPol[i] & -1) == 0;
        }
        return result;
    }

    @Override // com.mi.car.jsse.easysec.pqc.math.linearalgebra.GFElement
    public boolean isOne() {
        boolean result = true;
        for (int i = 0; i < this.mLength - 1 && result; i++) {
            result = result && (this.mPol[i] & -1) == -1;
        }
        if (result) {
            return result && (this.mPol[this.mLength + -1] & mMaxmask[this.mBit + -1]) == mMaxmask[this.mBit + -1];
        }
        return result;
    }

    @Override // com.mi.car.jsse.easysec.pqc.math.linearalgebra.GFElement
    public boolean equals(Object other) {
        if (other == null || !(other instanceof GF2nONBElement)) {
            return false;
        }
        GF2nONBElement otherElem = (GF2nONBElement) other;
        for (int i = 0; i < this.mLength; i++) {
            if (this.mPol[i] != otherElem.mPol[i]) {
                return false;
            }
        }
        return true;
    }

    @Override // com.mi.car.jsse.easysec.pqc.math.linearalgebra.GFElement
    public int hashCode() {
        return Arrays.hashCode(this.mPol);
    }

    @Override // com.mi.car.jsse.easysec.pqc.math.linearalgebra.GF2nElement
    public boolean testRightmostBit() {
        return (this.mPol[this.mLength + -1] & mBitmask[this.mBit + -1]) != 0;
    }

    /* access modifiers changed from: package-private */
    @Override // com.mi.car.jsse.easysec.pqc.math.linearalgebra.GF2nElement
    public boolean testBit(int index) {
        if (index < 0 || index > this.mDegree || (this.mPol[index >>> 6] & mBitmask[index & 63]) == 0) {
            return false;
        }
        return true;
    }

    private long[] getElement() {
        long[] result = new long[this.mPol.length];
        System.arraycopy(this.mPol, 0, result, 0, this.mPol.length);
        return result;
    }

    private long[] getElementReverseOrder() {
        long[] result = new long[this.mPol.length];
        for (int i = 0; i < this.mDegree; i++) {
            if (testBit((this.mDegree - i) - 1)) {
                int i2 = i >>> 6;
                result[i2] = result[i2] | mBitmask[i & 63];
            }
        }
        return result;
    }

    /* access modifiers changed from: package-private */
    public void reverseOrder() {
        this.mPol = getElementReverseOrder();
    }

    @Override // com.mi.car.jsse.easysec.pqc.math.linearalgebra.GFElement
    public GFElement add(GFElement addend) throws RuntimeException {
        GF2nONBElement result = new GF2nONBElement(this);
        result.addToThis(addend);
        return result;
    }

    @Override // com.mi.car.jsse.easysec.pqc.math.linearalgebra.GFElement
    public void addToThis(GFElement addend) throws RuntimeException {
        if (!(addend instanceof GF2nONBElement)) {
            throw new RuntimeException();
        } else if (!this.mField.equals(((GF2nONBElement) addend).mField)) {
            throw new RuntimeException();
        } else {
            for (int i = 0; i < this.mLength; i++) {
                long[] jArr = this.mPol;
                jArr[i] = jArr[i] ^ ((GF2nONBElement) addend).mPol[i];
            }
        }
    }

    @Override // com.mi.car.jsse.easysec.pqc.math.linearalgebra.GF2nElement
    public GF2nElement increase() {
        GF2nONBElement result = new GF2nONBElement(this);
        result.increaseThis();
        return result;
    }

    @Override // com.mi.car.jsse.easysec.pqc.math.linearalgebra.GF2nElement
    public void increaseThis() {
        addToThis(ONE((GF2nONBField) this.mField));
    }

    @Override // com.mi.car.jsse.easysec.pqc.math.linearalgebra.GFElement
    public GFElement multiply(GFElement factor) throws RuntimeException {
        GF2nONBElement result = new GF2nONBElement(this);
        result.multiplyThisBy(factor);
        return result;
    }

    @Override // com.mi.car.jsse.easysec.pqc.math.linearalgebra.GFElement
    public void multiplyThisBy(GFElement factor) throws RuntimeException {
        if (!(factor instanceof GF2nONBElement)) {
            throw new RuntimeException("The elements have different representation: not yet implemented");
        } else if (!this.mField.equals(((GF2nONBElement) factor).mField)) {
            throw new RuntimeException();
        } else if (equals(factor)) {
            squareThis();
        } else {
            long[] a = this.mPol;
            long[] b = ((GF2nONBElement) factor).mPol;
            long[] c = new long[this.mLength];
            int[][] m = ((GF2nONBField) this.mField).mMult;
            int degf = this.mLength - 1;
            long TWOTOMAXLONGM1 = mBitmask[63];
            long TWOTODEGB = mBitmask[this.mBit - 1];
            for (int k = 0; k < this.mDegree; k++) {
                int s = 0;
                for (int i = 0; i < this.mDegree; i++) {
                    int fielda = mIBY64[i];
                    int fieldb = mIBY64[m[i][0]];
                    int bitb = m[i][0] & 63;
                    if ((a[fielda] & mBitmask[i & 63]) != 0) {
                        if ((b[fieldb] & mBitmask[bitb]) != 0) {
                            s ^= 1;
                        }
                        if (m[i][1] != -1) {
                            if ((b[mIBY64[m[i][1]]] & mBitmask[m[i][1] & 63]) != 0) {
                                s ^= 1;
                            }
                        }
                    }
                }
                int fielda2 = mIBY64[k];
                int bita = k & 63;
                if (s != 0) {
                    c[fielda2] = c[fielda2] ^ mBitmask[bita];
                }
                if (this.mLength > 1) {
                    boolean old = (a[degf] & 1) == 1;
                    for (int i2 = degf - 1; i2 >= 0; i2--) {
                        boolean now = (a[i2] & 1) != 0;
                        a[i2] = a[i2] >>> 1;
                        if (old) {
                            a[i2] = a[i2] ^ TWOTOMAXLONGM1;
                        }
                        old = now;
                    }
                    a[degf] = a[degf] >>> 1;
                    if (old) {
                        a[degf] = a[degf] ^ TWOTODEGB;
                    }
                    boolean old2 = (b[degf] & 1) == 1;
                    for (int i3 = degf - 1; i3 >= 0; i3--) {
                        boolean now2 = (b[i3] & 1) != 0;
                        b[i3] = b[i3] >>> 1;
                        if (old2) {
                            b[i3] = b[i3] ^ TWOTOMAXLONGM1;
                        }
                        old2 = now2;
                    }
                    b[degf] = b[degf] >>> 1;
                    if (old2) {
                        b[degf] = b[degf] ^ TWOTODEGB;
                    }
                } else {
                    boolean old3 = (a[0] & 1) == 1;
                    a[0] = a[0] >>> 1;
                    if (old3) {
                        a[0] = a[0] ^ TWOTODEGB;
                    }
                    boolean old4 = (b[0] & 1) == 1;
                    b[0] = b[0] >>> 1;
                    if (old4) {
                        b[0] = b[0] ^ TWOTODEGB;
                    }
                }
            }
            assign(c);
        }
    }

    @Override // com.mi.car.jsse.easysec.pqc.math.linearalgebra.GF2nElement
    public GF2nElement square() {
        GF2nONBElement result = new GF2nONBElement(this);
        result.squareThis();
        return result;
    }

    @Override // com.mi.car.jsse.easysec.pqc.math.linearalgebra.GF2nElement
    public void squareThis() {
        long[] pol = getElement();
        int f = this.mLength - 1;
        int b = this.mBit - 1;
        long TWOTOMAXLONGM1 = mBitmask[63];
        boolean old = (pol[f] & mBitmask[b]) != 0;
        for (int i = 0; i < f; i++) {
            boolean now = (pol[i] & TWOTOMAXLONGM1) != 0;
            pol[i] = pol[i] << 1;
            if (old) {
                pol[i] = pol[i] ^ 1;
            }
            old = now;
        }
        boolean now2 = (pol[f] & mBitmask[b]) != 0;
        pol[f] = pol[f] << 1;
        if (old) {
            pol[f] = pol[f] ^ 1;
        }
        if (now2) {
            pol[f] = pol[f] ^ mBitmask[b + 1];
        }
        assign(pol);
    }

    @Override // com.mi.car.jsse.easysec.pqc.math.linearalgebra.GFElement
    public GFElement invert() throws ArithmeticException {
        GF2nONBElement result = new GF2nONBElement(this);
        result.invertThis();
        return result;
    }

    public void invertThis() throws ArithmeticException {
        if (isZero()) {
            throw new ArithmeticException();
        }
        int r = 31;
        boolean found = false;
        while (!found && r >= 0) {
            if ((((long) (this.mDegree - 1)) & mBitmask[r]) != 0) {
                found = true;
            }
            r--;
        }
        ZERO((GF2nONBField) this.mField);
        GF2nElement n = new GF2nONBElement(this);
        int k = 1;
        for (int i = (r + 1) - 1; i >= 0; i--) {
            GF2nElement m = (GF2nElement) n.clone();
            for (int j = 1; j <= k; j++) {
                m.squareThis();
            }
            n.multiplyThisBy(m);
            k <<= 1;
            if ((((long) (this.mDegree - 1)) & mBitmask[i]) != 0) {
                n.squareThis();
                n.multiplyThisBy(this);
                k++;
            }
        }
        n.squareThis();
    }

    @Override // com.mi.car.jsse.easysec.pqc.math.linearalgebra.GF2nElement
    public GF2nElement squareRoot() {
        GF2nONBElement result = new GF2nONBElement(this);
        result.squareRootThis();
        return result;
    }

    @Override // com.mi.car.jsse.easysec.pqc.math.linearalgebra.GF2nElement
    public void squareRootThis() {
        long[] pol = getElement();
        int f = this.mLength - 1;
        int b = this.mBit - 1;
        long TWOTOMAXLONGM1 = mBitmask[63];
        boolean old = (pol[0] & 1) != 0;
        for (int i = f; i >= 0; i--) {
            boolean now = (pol[i] & 1) != 0;
            pol[i] = pol[i] >>> 1;
            if (old) {
                if (i == f) {
                    pol[i] = pol[i] ^ mBitmask[b];
                } else {
                    pol[i] = pol[i] ^ TWOTOMAXLONGM1;
                }
            }
            old = now;
        }
        assign(pol);
    }

    @Override // com.mi.car.jsse.easysec.pqc.math.linearalgebra.GF2nElement
    public int trace() {
        int result = 0;
        int max = this.mLength - 1;
        for (int i = 0; i < max; i++) {
            for (int j = 0; j < 64; j++) {
                if ((this.mPol[i] & mBitmask[j]) != 0) {
                    result ^= 1;
                }
            }
        }
        int b = this.mBit;
        for (int j2 = 0; j2 < b; j2++) {
            if ((this.mPol[max] & mBitmask[j2]) != 0) {
                result ^= 1;
            }
        }
        return result;
    }

    @Override // com.mi.car.jsse.easysec.pqc.math.linearalgebra.GF2nElement
    public GF2nElement solveQuadraticEquation() throws RuntimeException {
        if (trace() == 1) {
            throw new RuntimeException();
        }
        long TWOTOMAXLONGM1 = mBitmask[63];
        long[] p = new long[this.mLength];
        long z = 0;
        for (int i = 0; i < this.mLength - 1; i++) {
            for (int j = 1; j < 64; j++) {
                if (((mBitmask[j] & this.mPol[i]) == 0 || (mBitmask[j - 1] & z) == 0) && !((this.mPol[i] & mBitmask[j]) == 0 && (mBitmask[j - 1] & z) == 0)) {
                    z ^= mBitmask[j];
                }
            }
            p[i] = z;
            z = (((TWOTOMAXLONGM1 & z) == 0 || (this.mPol[i + 1] & 1) != 1) && !((TWOTOMAXLONGM1 & z) == 0 && (this.mPol[i + 1] & 1) == 0)) ? 1 : 0;
        }
        int b = this.mDegree & 63;
        long LASTLONG = this.mPol[this.mLength - 1];
        for (int j2 = 1; j2 < b; j2++) {
            if (((mBitmask[j2] & LASTLONG) == 0 || (mBitmask[j2 - 1] & z) == 0) && !((mBitmask[j2] & LASTLONG) == 0 && (mBitmask[j2 - 1] & z) == 0)) {
                z ^= mBitmask[j2];
            }
        }
        p[this.mLength - 1] = z;
        return new GF2nONBElement((GF2nONBField) this.mField, p);
    }

    @Override // com.mi.car.jsse.easysec.pqc.math.linearalgebra.GFElement
    public String toString() {
        return toString(16);
    }

    @Override // com.mi.car.jsse.easysec.pqc.math.linearalgebra.GFElement
    public String toString(int radix) {
        String s = "";
        long[] a = getElement();
        int b = this.mBit;
        if (radix == 2) {
            for (int j = b - 1; j >= 0; j--) {
                s = (a[a.length - 1] & (1 << j)) == 0 ? s + "0" : s + "1";
            }
            for (int i = a.length - 2; i >= 0; i--) {
                for (int j2 = 63; j2 >= 0; j2--) {
                    s = (a[i] & mBitmask[j2]) == 0 ? s + "0" : s + "1";
                }
            }
        } else if (radix == 16) {
            char[] HEX_CHARS = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};
            for (int i2 = a.length - 1; i2 >= 0; i2--) {
                s = ((((((((((((((((s + HEX_CHARS[((int) (a[i2] >>> 60)) & 15]) + HEX_CHARS[((int) (a[i2] >>> 56)) & 15]) + HEX_CHARS[((int) (a[i2] >>> 52)) & 15]) + HEX_CHARS[((int) (a[i2] >>> 48)) & 15]) + HEX_CHARS[((int) (a[i2] >>> 44)) & 15]) + HEX_CHARS[((int) (a[i2] >>> 40)) & 15]) + HEX_CHARS[((int) (a[i2] >>> 36)) & 15]) + HEX_CHARS[((int) (a[i2] >>> 32)) & 15]) + HEX_CHARS[((int) (a[i2] >>> 28)) & 15]) + HEX_CHARS[((int) (a[i2] >>> 24)) & 15]) + HEX_CHARS[((int) (a[i2] >>> 20)) & 15]) + HEX_CHARS[((int) (a[i2] >>> 16)) & 15]) + HEX_CHARS[((int) (a[i2] >>> 12)) & 15]) + HEX_CHARS[((int) (a[i2] >>> 8)) & 15]) + HEX_CHARS[((int) (a[i2] >>> 4)) & 15]) + HEX_CHARS[((int) a[i2]) & 15]) + " ";
            }
        }
        return s;
    }

    @Override // com.mi.car.jsse.easysec.pqc.math.linearalgebra.GFElement
    public BigInteger toFlexiBigInt() {
        return new BigInteger(1, toByteArray());
    }

    @Override // com.mi.car.jsse.easysec.pqc.math.linearalgebra.GFElement
    public byte[] toByteArray() {
        int k = ((this.mDegree - 1) >> 3) + 1;
        byte[] result = new byte[k];
        for (int i = 0; i < k; i++) {
            result[(k - i) - 1] = (byte) ((int) ((this.mPol[i >>> 3] & (255 << ((i & 7) << 3))) >>> ((i & 7) << 3)));
        }
        return result;
    }
}
