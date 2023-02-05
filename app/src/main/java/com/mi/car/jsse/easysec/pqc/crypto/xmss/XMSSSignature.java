package com.mi.car.jsse.easysec.pqc.crypto.xmss;

import com.mi.car.jsse.easysec.pqc.crypto.xmss.XMSSReducedSignature;
import com.mi.car.jsse.easysec.util.Encodable;
import com.mi.car.jsse.easysec.util.Pack;
import java.io.IOException;

public final class XMSSSignature extends XMSSReducedSignature implements XMSSStoreableObjectInterface, Encodable {
    private final int index;
    private final byte[] random;

    private XMSSSignature(Builder builder) {
        super(builder);
        this.index = builder.index;
        int n = getParams().getTreeDigestSize();
        byte[] tmpRandom = builder.random;
        if (tmpRandom == null) {
            this.random = new byte[n];
        } else if (tmpRandom.length != n) {
            throw new IllegalArgumentException("size of random needs to be equal to size of digest");
        } else {
            this.random = tmpRandom;
        }
    }

    @Override // com.mi.car.jsse.easysec.util.Encodable
    public byte[] getEncoded() throws IOException {
        return toByteArray();
    }

    public static class Builder extends XMSSReducedSignature.Builder {
        private int index = 0;
        private final XMSSParameters params;
        private byte[] random = null;

        public Builder(XMSSParameters params2) {
            super(params2);
            this.params = params2;
        }

        public Builder withIndex(int val) {
            this.index = val;
            return this;
        }

        public Builder withRandom(byte[] val) {
            this.random = XMSSUtil.cloneArray(val);
            return this;
        }

        public Builder withSignature(byte[] val) {
            if (val == null) {
                throw new NullPointerException("signature == null");
            }
            int n = this.params.getTreeDigestSize();
            int len = this.params.getWOTSPlus().getParams().getLen();
            this.index = Pack.bigEndianToInt(val, 0);
            this.random = XMSSUtil.extractBytesAtOffset(val, 0 + 4, n);
            withReducedSignature(XMSSUtil.extractBytesAtOffset(val, n + 4, (len * n) + (this.params.getHeight() * n)));
            return this;
        }

        @Override // com.mi.car.jsse.easysec.pqc.crypto.xmss.XMSSReducedSignature.Builder
        public XMSSSignature build() {
            return new XMSSSignature(this);
        }
    }

    @Override // com.mi.car.jsse.easysec.pqc.crypto.xmss.XMSSReducedSignature, com.mi.car.jsse.easysec.pqc.crypto.xmss.XMSSStoreableObjectInterface
    public byte[] toByteArray() {
        byte[][] signature;
        int n = getParams().getTreeDigestSize();
        byte[] out = new byte[(4 + n + (getParams().getWOTSPlus().getParams().getLen() * n) + (getParams().getHeight() * n))];
        Pack.intToBigEndian(this.index, out, 0);
        XMSSUtil.copyBytesAtOffset(out, this.random, 0 + 4);
        int position = n + 4;
        for (byte[] bArr : getWOTSPlusSignature().toByteArray()) {
            XMSSUtil.copyBytesAtOffset(out, bArr, position);
            position += n;
        }
        for (int i = 0; i < getAuthPath().size(); i++) {
            XMSSUtil.copyBytesAtOffset(out, getAuthPath().get(i).getValue(), position);
            position += n;
        }
        return out;
    }

    public int getIndex() {
        return this.index;
    }

    public byte[] getRandom() {
        return XMSSUtil.cloneArray(this.random);
    }
}
