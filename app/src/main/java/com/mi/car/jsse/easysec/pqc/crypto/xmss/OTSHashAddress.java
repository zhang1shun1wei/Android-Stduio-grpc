package com.mi.car.jsse.easysec.pqc.crypto.xmss;

import com.mi.car.jsse.easysec.pqc.crypto.xmss.XMSSAddress;
import com.mi.car.jsse.easysec.util.Pack;

/* access modifiers changed from: package-private */
public final class OTSHashAddress extends XMSSAddress {
    private static final int TYPE = 0;
    private final int chainAddress;
    private final int hashAddress;
    private final int otsAddress;

    private OTSHashAddress(Builder builder) {
        super(builder);
        this.otsAddress = builder.otsAddress;
        this.chainAddress = builder.chainAddress;
        this.hashAddress = builder.hashAddress;
    }

    /* access modifiers changed from: protected */
    public static class Builder extends XMSSAddress.Builder<Builder> {
        private int chainAddress = 0;
        private int hashAddress = 0;
        private int otsAddress = 0;

        protected Builder() {
            super(0);
        }

        /* access modifiers changed from: protected */
        public Builder withOTSAddress(int val) {
            this.otsAddress = val;
            return this;
        }

        /* access modifiers changed from: protected */
        public Builder withChainAddress(int val) {
            this.chainAddress = val;
            return this;
        }

        /* access modifiers changed from: protected */
        public Builder withHashAddress(int val) {
            this.hashAddress = val;
            return this;
        }

        /* access modifiers changed from: protected */
        @Override // com.mi.car.jsse.easysec.pqc.crypto.xmss.XMSSAddress.Builder
        public XMSSAddress build() {
            return new OTSHashAddress(this);
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
        Pack.intToBigEndian(this.otsAddress, byteRepresentation, 16);
        Pack.intToBigEndian(this.chainAddress, byteRepresentation, 20);
        Pack.intToBigEndian(this.hashAddress, byteRepresentation, 24);
        return byteRepresentation;
    }

    /* access modifiers changed from: protected */
    public int getOTSAddress() {
        return this.otsAddress;
    }

    /* access modifiers changed from: protected */
    public int getChainAddress() {
        return this.chainAddress;
    }

    /* access modifiers changed from: protected */
    public int getHashAddress() {
        return this.hashAddress;
    }
}
