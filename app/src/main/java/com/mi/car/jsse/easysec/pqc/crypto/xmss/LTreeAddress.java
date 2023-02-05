package com.mi.car.jsse.easysec.pqc.crypto.xmss;

import com.mi.car.jsse.easysec.pqc.crypto.xmss.XMSSAddress;
import com.mi.car.jsse.easysec.util.Pack;

/* access modifiers changed from: package-private */
public final class LTreeAddress extends XMSSAddress {
    private static final int TYPE = 1;
    private final int lTreeAddress;
    private final int treeHeight;
    private final int treeIndex;

    private LTreeAddress(Builder builder) {
        super(builder);
        this.lTreeAddress = builder.lTreeAddress;
        this.treeHeight = builder.treeHeight;
        this.treeIndex = builder.treeIndex;
    }

    /* access modifiers changed from: protected */
    public static class Builder extends XMSSAddress.Builder<Builder> {
        private int lTreeAddress = 0;
        private int treeHeight = 0;
        private int treeIndex = 0;

        protected Builder() {
            super(1);
        }

        /* access modifiers changed from: protected */
        public Builder withLTreeAddress(int val) {
            this.lTreeAddress = val;
            return this;
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
            return new LTreeAddress(this);
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
        Pack.intToBigEndian(this.lTreeAddress, byteRepresentation, 16);
        Pack.intToBigEndian(this.treeHeight, byteRepresentation, 20);
        Pack.intToBigEndian(this.treeIndex, byteRepresentation, 24);
        return byteRepresentation;
    }

    /* access modifiers changed from: protected */
    public int getLTreeAddress() {
        return this.lTreeAddress;
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
