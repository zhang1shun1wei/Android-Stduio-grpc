package com.mi.car.jsse.easysec.pqc.crypto.qtesla;

final class IntSlicer {
    private int base;
    private final int[] values;

    IntSlicer(int[] values2, int base2) {
        this.values = values2;
        this.base = base2;
    }

    /* access modifiers changed from: package-private */
    public final int at(int index) {
        return this.values[this.base + index];
    }

    /* access modifiers changed from: package-private */
    public final int at(int index, int value) {
        this.values[this.base + index] = value;
        return value;
    }

    /* access modifiers changed from: package-private */
    public final int at(int index, long value) {
        int i = (int) value;
        this.values[this.base + index] = i;
        return i;
    }

    /* access modifiers changed from: package-private */
    public final IntSlicer from(int o) {
        return new IntSlicer(this.values, this.base + o);
    }

    /* access modifiers changed from: package-private */
    public final void incBase(int paramM) {
        this.base += paramM;
    }

    /* access modifiers changed from: package-private */
    public final IntSlicer copy() {
        return new IntSlicer(this.values, this.base);
    }
}
