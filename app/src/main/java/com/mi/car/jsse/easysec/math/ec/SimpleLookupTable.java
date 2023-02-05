package com.mi.car.jsse.easysec.math.ec;

public class SimpleLookupTable extends AbstractECLookupTable {
    private final ECPoint[] points;

    private static ECPoint[] copy(ECPoint[] points2, int off, int len) {
        ECPoint[] result = new ECPoint[len];
        for (int i = 0; i < len; i++) {
            result[i] = points2[off + i];
        }
        return result;
    }

    public SimpleLookupTable(ECPoint[] points2, int off, int len) {
        this.points = copy(points2, off, len);
    }

    @Override // com.mi.car.jsse.easysec.math.ec.ECLookupTable
    public int getSize() {
        return this.points.length;
    }

    @Override // com.mi.car.jsse.easysec.math.ec.ECLookupTable
    public ECPoint lookup(int index) {
        throw new UnsupportedOperationException("Constant-time lookup not supported");
    }

    @Override // com.mi.car.jsse.easysec.math.ec.AbstractECLookupTable, com.mi.car.jsse.easysec.math.ec.ECLookupTable
    public ECPoint lookupVar(int index) {
        return this.points[index];
    }
}
