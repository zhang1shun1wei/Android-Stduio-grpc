package com.mi.car.jsse.easysec.pqc.crypto.xmss;

import com.mi.car.jsse.easysec.util.Pack;

public abstract class XMSSAddress {
    private final int keyAndMask;
    private final int layerAddress;
    private final long treeAddress;
    private final int type;

    protected XMSSAddress(Builder builder) {
        this.layerAddress = builder.layerAddress;
        this.treeAddress = builder.treeAddress;
        this.type = builder.type;
        this.keyAndMask = builder.keyAndMask;
    }

    /* access modifiers changed from: protected */
    public static abstract class Builder<T extends Builder> {
        private int keyAndMask = 0;
        private int layerAddress = 0;
        private long treeAddress = 0;
        private final int type;

        /* access modifiers changed from: protected */
        public abstract XMSSAddress build();

        /* access modifiers changed from: protected */
        public abstract T getThis();

        protected Builder(int type2) {
            this.type = type2;
        }

        /* access modifiers changed from: protected */
        public T withLayerAddress(int val) {
            this.layerAddress = val;
            return getThis();
        }

        /* access modifiers changed from: protected */
        public T withTreeAddress(long val) {
            this.treeAddress = val;
            return getThis();
        }

        /* access modifiers changed from: protected */
        public T withKeyAndMask(int val) {
            this.keyAndMask = val;
            return getThis();
        }
    }

    /* access modifiers changed from: protected */
    public byte[] toByteArray() {
        byte[] byteRepresentation = new byte[32];
        Pack.intToBigEndian(this.layerAddress, byteRepresentation, 0);
        Pack.longToBigEndian(this.treeAddress, byteRepresentation, 4);
        Pack.intToBigEndian(this.type, byteRepresentation, 12);
        Pack.intToBigEndian(this.keyAndMask, byteRepresentation, 28);
        return byteRepresentation;
    }

    /* access modifiers changed from: protected */
    public final int getLayerAddress() {
        return this.layerAddress;
    }

    /* access modifiers changed from: protected */
    public final long getTreeAddress() {
        return this.treeAddress;
    }

    public final int getType() {
        return this.type;
    }

    public final int getKeyAndMask() {
        return this.keyAndMask;
    }
}
