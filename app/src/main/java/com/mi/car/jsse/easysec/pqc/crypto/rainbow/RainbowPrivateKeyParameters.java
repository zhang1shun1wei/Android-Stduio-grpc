package com.mi.car.jsse.easysec.pqc.crypto.rainbow;

public class RainbowPrivateKeyParameters extends RainbowKeyParameters {
    private short[][] A1inv;
    private short[][] A2inv;
    private short[] b1;
    private short[] b2;
    private Layer[] layers;
    private int[] vi;

    public RainbowPrivateKeyParameters(short[][] A1inv2, short[] b12, short[][] A2inv2, short[] b22, int[] vi2, Layer[] layers2) {
        super(true, vi2[vi2.length - 1] - vi2[0]);
        this.A1inv = A1inv2;
        this.b1 = b12;
        this.A2inv = A2inv2;
        this.b2 = b22;
        this.vi = vi2;
        this.layers = layers2;
    }

    public short[] getB1() {
        return this.b1;
    }

    public short[][] getInvA1() {
        return this.A1inv;
    }

    public short[] getB2() {
        return this.b2;
    }

    public short[][] getInvA2() {
        return this.A2inv;
    }

    public Layer[] getLayers() {
        return this.layers;
    }

    public int[] getVi() {
        return this.vi;
    }
}
