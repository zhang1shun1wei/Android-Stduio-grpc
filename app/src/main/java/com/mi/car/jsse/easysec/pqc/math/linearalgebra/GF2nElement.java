package com.mi.car.jsse.easysec.pqc.math.linearalgebra;

public abstract class GF2nElement implements GFElement {
    protected int mDegree;
    protected GF2nField mField;

    /* access modifiers changed from: package-private */
    public abstract void assignOne();

    /* access modifiers changed from: package-private */
    public abstract void assignZero();

    @Override // com.mi.car.jsse.easysec.pqc.math.linearalgebra.GFElement
    public abstract Object clone();

    public abstract GF2nElement increase();

    public abstract void increaseThis();

    public abstract GF2nElement solveQuadraticEquation() throws RuntimeException;

    public abstract GF2nElement square();

    public abstract GF2nElement squareRoot();

    public abstract void squareRootThis();

    public abstract void squareThis();

    /* access modifiers changed from: package-private */
    public abstract boolean testBit(int i);

    public abstract boolean testRightmostBit();

    public abstract int trace();

    public final GF2nField getField() {
        return this.mField;
    }

    @Override // com.mi.car.jsse.easysec.pqc.math.linearalgebra.GFElement
    public final GFElement subtract(GFElement minuend) {
        return add(minuend);
    }

    @Override // com.mi.car.jsse.easysec.pqc.math.linearalgebra.GFElement
    public final void subtractFromThis(GFElement minuend) {
        addToThis(minuend);
    }

    public final GF2nElement convert(GF2nField basis) {
        return this.mField.convert(this, basis);
    }
}
