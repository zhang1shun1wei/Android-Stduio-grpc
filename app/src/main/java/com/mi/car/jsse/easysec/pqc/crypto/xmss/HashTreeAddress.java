package com.mi.car.jsse.easysec.pqc.crypto.xmss;

import com.mi.car.jsse.easysec.pqc.crypto.xmss.XMSSAddress;
import com.mi.car.jsse.easysec.util.Pack;

/* access modifiers changed from: package-private */
public final class HashTreeAddress extends XMSSAddress {
    private static final int PADDING = 0;
    private static final int TYPE = 2;
    private final int padding;
    private final int treeHeight;
    private final int treeIndex;

    private HashTreeAddress(Builder builder) {
        super(builder);
        this.padding = 0;
        this.treeHeight = builder.treeHeight;
        this.treeIndex = builder.treeIndex;
    }

    /* access modifiers changed from: protected */
    public static class Builder extends XMSSAddress.Builder<Builder> {
        private int treeHeight = 0;
        private int treeIndex = 0;

        protected Builder() {
            super(2);
        }

        /* access modifiers changed from: protected */
        public Builder withTreeHeight(int val) {
            this.treeHeight = val;
            return this;
        }

        /* access modifiers changed from: protected */
        public Builder withTreeIndex(int val) {
            this.treeIndex = val;
            return this;
        }

        /* access modifiers changed from: protected */
        @Override // com.mi.car.jsse.easysec.pqc.crypto.xmss.XMSSAddress.Builder
        public XMSSAddress build() {
            return new HashTreeAddress(this);
        }

        /* access modifiers changed from: protected */
        @Override // com.mi.car.jsse.easysec.pqc.crypto.xmss.XMSSAddress.Builder
        public Builder getThis() {
            return this;
        }
    }

    /* access modifiers changed from: protected */
    @Override // com.mi.car.jsse.easysec.pqc.crypto.xmss.XMSSAddress
    public byte[] toByteArray() {
        byte[] byteRepresentation = super.toByteArray();
        Pack.intToBigEndian(this.padding, byteRepresentation, 16);
        Pack.intToBigEndian(this.treeHeight, byteRepresentation, 20);
        Pack.intToBigEndian(this.treeIndex, byteRepresentation, 24);
        return byteRepresentation;
    }

    /* access modifiers changed from: protected */
    public int getPadding() {
        return this.padding;
    }

    /* access modifiers changed from: protected */
    public int getTreeHeight() {
        return this.treeHeight;
    }

    /* access modifiers changed from: protected */
    public int getTreeIndex() {
        return this.treeIndex;
    }
}
