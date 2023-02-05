package com.mi.car.jsse.easysec.pqc.crypto.gmss;

import com.mi.car.jsse.easysec.util.Arrays;

public class GMSSParameters {
    private int[] K;
    private int[] heightOfTrees;
    private int numOfLayers;
    private int[] winternitzParameter;

    public GMSSParameters(int layers, int[] heightOfTrees2, int[] winternitzParameter2, int[] K2) throws IllegalArgumentException {
        init(layers, heightOfTrees2, winternitzParameter2, K2);
    }

    private void init(int layers, int[] heightOfTrees2, int[] winternitzParameter2, int[] K2) throws IllegalArgumentException {
        boolean valid = true;
        String errMsg = "";
        this.numOfLayers = layers;
        if (!(this.numOfLayers == winternitzParameter2.length && this.numOfLayers == heightOfTrees2.length && this.numOfLayers == K2.length)) {
            valid = false;
            errMsg = "Unexpected parameterset format";
        }
        for (int i = 0; i < this.numOfLayers; i++) {
            if (K2[i] < 2 || (heightOfTrees2[i] - K2[i]) % 2 != 0) {
                valid = false;
                errMsg = "Wrong parameter K (K >= 2 and H-K even required)!";
            }
            if (heightOfTrees2[i] < 4 || winternitzParameter2[i] < 2) {
                valid = false;
                errMsg = "Wrong parameter H or w (H > 3 and w > 1 required)!";
            }
        }
        if (valid) {
            this.heightOfTrees = Arrays.clone(heightOfTrees2);
            this.winternitzParameter = Arrays.clone(winternitzParameter2);
            this.K = Arrays.clone(K2);
            return;
        }
        throw new IllegalArgumentException(errMsg);
    }

    public GMSSParameters(int keySize) throws IllegalArgumentException {
        if (keySize <= 10) {
            int[] defh = {10};
            init(defh.length, defh, new int[]{3}, new int[]{2});
        } else if (keySize <= 20) {
            int[] defh2 = {10, 10};
            init(defh2.length, defh2, new int[]{5, 4}, new int[]{2, 2});
        } else {
            int[] defh3 = {10, 10, 10, 10};
            init(defh3.length, defh3, new int[]{9, 9, 9, 3}, new int[]{2, 2, 2, 2});
        }
    }

    public int getNumOfLayers() {
        return this.numOfLayers;
    }

    public int[] getHeightOfTrees() {
        return Arrays.clone(this.heightOfTrees);
    }

    public int[] getWinternitzParameter() {
        return Arrays.clone(this.winternitzParameter);
    }

    public int[] getK() {
        return Arrays.clone(this.K);
    }
}
