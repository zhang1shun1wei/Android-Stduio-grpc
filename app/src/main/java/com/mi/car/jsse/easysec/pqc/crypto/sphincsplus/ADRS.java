package com.mi.car.jsse.easysec.pqc.crypto.sphincsplus;

import com.mi.car.jsse.easysec.util.Arrays;
import com.mi.car.jsse.easysec.util.Pack;

class ADRS {
    public static final int FORS_ROOTS = 4;
    public static final int FORS_TREE = 3;
    static final int OFFSET_CHAIN_ADDR = 24;
    static final int OFFSET_HASH_ADDR = 28;
    static final int OFFSET_KP_ADDR = 20;
    static final int OFFSET_LAYER = 0;
    static final int OFFSET_TREE = 4;
    static final int OFFSET_TREE_HGT = 24;
    static final int OFFSET_TREE_INDEX = 28;
    static final int OFFSET_TYPE = 16;
    public static final int TREE = 2;
    public static final int WOTS_HASH = 0;
    public static final int WOTS_PK = 1;
    final byte[] value;

    ADRS() {
        this.value = new byte[32];
    }

    ADRS(ADRS adrs) {
        this.value = new byte[32];
        System.arraycopy(adrs.value, 0, this.value, 0, adrs.value.length);
    }

    public void setLayerAddress(int layer) {
        Pack.intToBigEndian(layer, this.value, 0);
    }

    public int getLayerAddress() {
        return Pack.bigEndianToInt(this.value, 0);
    }

    public void setTreeAddress(long tree) {
        Pack.longToBigEndian(tree, this.value, 8);
    }

    public long getTreeAddress() {
        return Pack.bigEndianToLong(this.value, 8);
    }

    public void setTreeHeight(int height) {
        Pack.intToBigEndian(height, this.value, 24);
    }

    public int getTreeHeight() {
        return Pack.bigEndianToInt(this.value, 24);
    }

    public void setTreeIndex(int index) {
        Pack.intToBigEndian(index, this.value, 28);
    }

    public int getTreeIndex() {
        return Pack.bigEndianToInt(this.value, 28);
    }

    public void setType(int type) {
        Pack.intToBigEndian(type, this.value, 16);
        Arrays.fill(this.value, 20, this.value.length, (byte) 0);
    }

    public int getType() {
        return Pack.bigEndianToInt(this.value, 16);
    }

    public void setKeyPairAddress(int keyPairAddr) {
        Pack.intToBigEndian(keyPairAddr, this.value, 20);
    }

    public int getKeyPairAddress() {
        return Pack.bigEndianToInt(this.value, 20);
    }

    public void setHashAddress(int hashAddr) {
        Pack.intToBigEndian(hashAddr, this.value, 28);
    }

    public void setChainAddress(int chainAddr) {
        Pack.intToBigEndian(chainAddr, this.value, 24);
    }
}
