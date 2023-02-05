package com.mi.car.jsse.easysec.pqc.crypto.xmss;

import java.lang.reflect.Array;
import java.util.ArrayList;
import java.util.List;

public class XMSSReducedSignature implements XMSSStoreableObjectInterface {
    private final List<XMSSNode> authPath;
    private final XMSSParameters params;
    private final WOTSPlusSignature wotsPlusSignature;

    protected XMSSReducedSignature(Builder builder) {
        this.params = builder.params;
        if (this.params == null) {
            throw new NullPointerException("params == null");
        }
        int n = this.params.getTreeDigestSize();
        int len = this.params.getWOTSPlus().getParams().getLen();
        int height = this.params.getHeight();
        byte[] reducedSignature = builder.reducedSignature;
        if (reducedSignature != null) {
            if (reducedSignature.length != (len * n) + (height * n)) {
                throw new IllegalArgumentException("signature has wrong size");
            }
            int position = 0;
            byte[][] wotsPlusSignature2 = new byte[len][];
            for (int i = 0; i < wotsPlusSignature2.length; i++) {
                wotsPlusSignature2[i] = XMSSUtil.extractBytesAtOffset(reducedSignature, position, n);
                position += n;
            }
            this.wotsPlusSignature = new WOTSPlusSignature(this.params.getWOTSPlus().getParams(), wotsPlusSignature2);
            List<XMSSNode> nodeList = new ArrayList<>();
            for (int i2 = 0; i2 < height; i2++) {
                nodeList.add(new XMSSNode(i2, XMSSUtil.extractBytesAtOffset(reducedSignature, position, n)));
                position += n;
            }
            this.authPath = nodeList;
            return;
        }
        WOTSPlusSignature tmpSignature = builder.wotsPlusSignature;
        if (tmpSignature != null) {
            this.wotsPlusSignature = tmpSignature;
        } else {
            this.wotsPlusSignature = new WOTSPlusSignature(this.params.getWOTSPlus().getParams(), (byte[][]) Array.newInstance(Byte.TYPE, len, n));
        }
        List<XMSSNode> tmpAuthPath = builder.authPath;
        if (tmpAuthPath == null) {
            this.authPath = new ArrayList();
        } else if (tmpAuthPath.size() != height) {
            throw new IllegalArgumentException("size of authPath needs to be equal to height of tree");
        } else {
            this.authPath = tmpAuthPath;
        }
    }

    public static class Builder {
        private List<XMSSNode> authPath = null;
        private final XMSSParameters params;
        private byte[] reducedSignature = null;
        private WOTSPlusSignature wotsPlusSignature = null;

        public Builder(XMSSParameters params2) {
            this.params = params2;
        }

        public Builder withWOTSPlusSignature(WOTSPlusSignature val) {
            this.wotsPlusSignature = val;
            return this;
        }

        public Builder withAuthPath(List<XMSSNode> val) {
            this.authPath = val;
            return this;
        }

        public Builder withReducedSignature(byte[] val) {
            this.reducedSignature = XMSSUtil.cloneArray(val);
            return this;
        }

        public XMSSReducedSignature build() {
            return new XMSSReducedSignature(this);
        }
    }

    @Override // com.mi.car.jsse.easysec.pqc.crypto.xmss.XMSSStoreableObjectInterface
    public byte[] toByteArray() {
        byte[][] signature;
        int n = this.params.getTreeDigestSize();
        byte[] out = new byte[((this.params.getWOTSPlus().getParams().getLen() * n) + (this.params.getHeight() * n))];
        int position = 0;
        for (byte[] bArr : this.wotsPlusSignature.toByteArray()) {
            XMSSUtil.copyBytesAtOffset(out, bArr, position);
            position += n;
        }
        for (int i = 0; i < this.authPath.size(); i++) {
            XMSSUtil.copyBytesAtOffset(out, this.authPath.get(i).getValue(), position);
            position += n;
        }
        return out;
    }

    public XMSSParameters getParams() {
        return this.params;
    }

    public WOTSPlusSignature getWOTSPlusSignature() {
        return this.wotsPlusSignature;
    }

    public List<XMSSNode> getAuthPath() {
        return this.authPath;
    }
}
