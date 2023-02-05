package com.mi.car.jsse.easysec.pqc.crypto.rainbow;

import com.mi.car.jsse.easysec.crypto.CipherParameters;

public class RainbowParameters implements CipherParameters {
    private final int[] DEFAULT_VI;
    private int[] vi;

    public RainbowParameters() {
        this.DEFAULT_VI = new int[]{6, 12, 17, 22, 33};
        this.vi = this.DEFAULT_VI;
    }

    public RainbowParameters(int[] vi2) {
        this.DEFAULT_VI = new int[]{6, 12, 17, 22, 33};
        this.vi = vi2;
        checkParams();
    }

    private void checkParams() {
        if (this.vi == null) {
            throw new IllegalArgumentException("no layers defined.");
        } else if (this.vi.length > 1) {
            for (int i = 0; i < this.vi.length - 1; i++) {
                if (this.vi[i] >= this.vi[i + 1]) {
                    throw new IllegalArgumentException("v[i] has to be smaller than v[i+1]");
                }
            }
        } else {
            throw new IllegalArgumentException("Rainbow needs at least 1 layer, such that v1 < v2.");
        }
    }

    public int getNumOfLayers() {
        return this.vi.length - 1;
    }

    public int getDocLength() {
        return this.vi[this.vi.length - 1] - this.vi[0];
    }

    public int[] getVi() {
        return this.vi;
    }
}
