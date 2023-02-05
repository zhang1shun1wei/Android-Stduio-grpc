package com.mi.car.jsse.easysec.pqc.crypto.xmss;

import com.mi.car.jsse.easysec.pqc.crypto.xmss.XMSSReducedSignature;
import com.mi.car.jsse.easysec.util.Arrays;
import com.mi.car.jsse.easysec.util.Encodable;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

public final class XMSSMTSignature implements XMSSStoreableObjectInterface, Encodable {
    private final long index;
    private final XMSSMTParameters params;
    private final byte[] random;
    private final List<XMSSReducedSignature> reducedSignatures;

    private XMSSMTSignature(Builder builder) {
        this.params = builder.params;
        if (this.params == null) {
            throw new NullPointerException("params == null");
        }
        int n = this.params.getTreeDigestSize();
        byte[] signature = builder.signature;
        if (signature != null) {
            int len = this.params.getWOTSPlus().getParams().getLen();
            int indexSize = (int) Math.ceil(((double) this.params.getHeight()) / 8.0d);
            int reducedSignatureSizeSingle = ((this.params.getHeight() / this.params.getLayers()) + len) * n;
            if (signature.length != indexSize + n + (reducedSignatureSizeSingle * this.params.getLayers())) {
                throw new IllegalArgumentException("signature has wrong size");
            }
            this.index = XMSSUtil.bytesToXBigEndian(signature, 0, indexSize);
            if (!XMSSUtil.isIndexValid(this.params.getHeight(), this.index)) {
                throw new IllegalArgumentException("index out of bounds");
            }
            int position = 0 + indexSize;
            this.random = XMSSUtil.extractBytesAtOffset(signature, position, n);
            this.reducedSignatures = new ArrayList();
            for (int position2 = position + n; position2 < signature.length; position2 += reducedSignatureSizeSingle) {
                this.reducedSignatures.add(new XMSSReducedSignature.Builder(this.params.getXMSSParameters()).withReducedSignature(XMSSUtil.extractBytesAtOffset(signature, position2, reducedSignatureSizeSingle)).build());
            }
            return;
        }
        this.index = builder.index;
        byte[] tmpRandom = builder.random;
        if (tmpRandom == null) {
            this.random = new byte[n];
        } else if (tmpRandom.length != n) {
            throw new IllegalArgumentException("size of random needs to be equal to size of digest");
        } else {
            this.random = tmpRandom;
        }
        List<XMSSReducedSignature> tmpReducedSignatures = builder.reducedSignatures;
        if (tmpReducedSignatures != null) {
            this.reducedSignatures = tmpReducedSignatures;
        } else {
            this.reducedSignatures = new ArrayList();
        }
    }

    @Override // com.mi.car.jsse.easysec.util.Encodable
    public byte[] getEncoded() throws IOException {
        return toByteArray();
    }

    public static class Builder {
        private long index = 0;
        private final XMSSMTParameters params;
        private byte[] random = null;
        private List<XMSSReducedSignature> reducedSignatures = null;
        private byte[] signature = null;

        public Builder(XMSSMTParameters params2) {
            this.params = params2;
        }

        public Builder withIndex(long val) {
            this.index = val;
            return this;
        }

        public Builder withRandom(byte[] val) {
            this.random = XMSSUtil.cloneArray(val);
            return this;
        }

        public Builder withReducedSignatures(List<XMSSReducedSignature> val) {
            this.reducedSignatures = val;
            return this;
        }

        public Builder withSignature(byte[] val) {
            this.signature = Arrays.clone(val);
            return this;
        }

        public XMSSMTSignature build() {
            return new XMSSMTSignature(this);
        }
    }

    @Override // com.mi.car.jsse.easysec.pqc.crypto.xmss.XMSSStoreableObjectInterface
    public byte[] toByteArray() {
        int n = this.params.getTreeDigestSize();
        int len = this.params.getWOTSPlus().getParams().getLen();
        int indexSize = (int) Math.ceil(((double) this.params.getHeight()) / 8.0d);
        int reducedSignatureSizeSingle = ((this.params.getHeight() / this.params.getLayers()) + len) * n;
        byte[] out = new byte[(indexSize + n + (reducedSignatureSizeSingle * this.params.getLayers()))];
        XMSSUtil.copyBytesAtOffset(out, XMSSUtil.toBytesBigEndian(this.index, indexSize), 0);
        int position = 0 + indexSize;
        XMSSUtil.copyBytesAtOffset(out, this.random, position);
        int position2 = position + n;
        for (XMSSReducedSignature reducedSignature : this.reducedSignatures) {
            XMSSUtil.copyBytesAtOffset(out, reducedSignature.toByteArray(), position2);
            position2 += reducedSignatureSizeSingle;
        }
        return out;
    }

    public long getIndex() {
        return this.index;
    }

    public byte[] getRandom() {
        return XMSSUtil.cloneArray(this.random);
    }

    public List<XMSSReducedSignature> getReducedSignatures() {
        return this.reducedSignatures;
    }
}
