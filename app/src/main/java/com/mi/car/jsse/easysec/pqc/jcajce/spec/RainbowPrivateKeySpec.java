package com.mi.car.jsse.easysec.pqc.jcajce.spec;

import com.mi.car.jsse.easysec.pqc.crypto.rainbow.Layer;
import java.security.spec.KeySpec;

public class RainbowPrivateKeySpec implements KeySpec {
    private short[][] A1inv;
    private short[][] A2inv;
    private short[] b1;
    private short[] b2;
    private Layer[] layers;
    private int[] vi;

    public RainbowPrivateKeySpec(short[][] A1inv2, short[] b12, short[][] A2inv2, short[] b22, int[] vi2, Layer[] layers2) {
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
