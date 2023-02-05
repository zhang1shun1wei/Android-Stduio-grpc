package com.mi.car.jsse.easysec.pqc.crypto.xmss;

import com.mi.car.jsse.easysec.util.Encodable;
import com.mi.car.jsse.easysec.util.Pack;
import java.io.IOException;

public final class XMSSMTPublicKeyParameters extends XMSSMTKeyParameters implements XMSSStoreableObjectInterface, Encodable {
    private final int oid;
    private final XMSSMTParameters params;
    private final byte[] publicSeed;
    private final byte[] root;

    private XMSSMTPublicKeyParameters(Builder builder) {
        super(false, builder.params.getTreeDigest());
        this.params = builder.params;
        if (this.params == null) {
            throw new NullPointerException("params == null");
        }
        int n = this.params.getTreeDigestSize();
        byte[] publicKey = builder.publicKey;
        if (publicKey == null) {
            if (this.params.getOid() != null) {
                this.oid = this.params.getOid().getOid();
            } else {
                this.oid = 0;
            }
            byte[] tmpRoot = builder.root;
            if (tmpRoot == null) {
                this.root = new byte[n];
            } else if (tmpRoot.length != n) {
                throw new IllegalArgumentException("length of root must be equal to length of digest");
            } else {
                this.root = tmpRoot;
            }
            byte[] tmpPublicSeed = builder.publicSeed;
            if (tmpPublicSeed == null) {
                this.publicSeed = new byte[n];
            } else if (tmpPublicSeed.length != n) {
                throw new IllegalArgumentException("length of publicSeed must be equal to length of digest");
            } else {
                this.publicSeed = tmpPublicSeed;
            }
        } else if (publicKey.length == n + n) {
            this.oid = 0;
            this.root = XMSSUtil.extractBytesAtOffset(publicKey, 0, n);
            this.publicSeed = XMSSUtil.extractBytesAtOffset(publicKey, 0 + n, n);
        } else if (publicKey.length == 4 + n + n) {
            this.oid = Pack.bigEndianToInt(publicKey, 0);
            this.root = XMSSUtil.extractBytesAtOffset(publicKey, 0 + 4, n);
            this.publicSeed = XMSSUtil.extractBytesAtOffset(publicKey, n + 4, n);
        } else {
            throw new IllegalArgumentException("public key has wrong size");
        }
    }

    @Override // com.mi.car.jsse.easysec.util.Encodable
    public byte[] getEncoded() throws IOException {
        return toByteArray();
    }

    public static class Builder {
        private final XMSSMTParameters params;
        private byte[] publicKey = null;
        private byte[] publicSeed = null;
        private byte[] root = null;

        public Builder(XMSSMTParameters params2) {
            this.params = params2;
        }

        public Builder withRoot(byte[] val) {
            this.root = XMSSUtil.cloneArray(val);
            return this;
        }

        public Builder withPublicSeed(byte[] val) {
            this.publicSeed = XMSSUtil.cloneArray(val);
            return this;
        }

        public Builder withPublicKey(byte[] val) {
            this.publicKey = XMSSUtil.cloneArray(val);
            return this;
        }

        public XMSSMTPublicKeyParameters build() {
            return new XMSSMTPublicKeyParameters(this);
        }
    }

    @Override // com.mi.car.jsse.easysec.pqc.crypto.xmss.XMSSStoreableObjectInterface
    public byte[] toByteArray() {
        byte[] out;
        int n = this.params.getTreeDigestSize();
        int position = 0;
        if (this.oid != 0) {
            out = new byte[(4 + n + n)];
            Pack.intToBigEndian(this.oid, out, 0);
            position = 0 + 4;
        } else {
            out = new byte[(n + n)];
        }
        XMSSUtil.copyBytesAtOffset(out, this.root, position);
        XMSSUtil.copyBytesAtOffset(out, this.publicSeed, position + n);
        return out;
    }

    public byte[] getRoot() {
        return XMSSUtil.cloneArray(this.root);
    }

    public byte[] getPublicSeed() {
        return XMSSUtil.cloneArray(this.publicSeed);
    }

    public XMSSMTParameters getParameters() {
        return this.params;
    }
}
