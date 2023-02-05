package com.mi.car.jsse.easysec.pqc.crypto.xmss;

import com.mi.car.jsse.easysec.util.Arrays;
import com.mi.car.jsse.easysec.util.Encodable;
import java.io.IOException;

public final class XMSSMTPrivateKeyParameters extends XMSSMTKeyParameters implements XMSSStoreableObjectInterface, Encodable {
    private volatile BDSStateMap bdsState;
    private volatile long index;
    private final XMSSMTParameters params;
    private final byte[] publicSeed;
    private final byte[] root;
    private final byte[] secretKeyPRF;
    private final byte[] secretKeySeed;
    private volatile boolean used;

    private XMSSMTPrivateKeyParameters(Builder builder) {
        super(true, builder.params.getTreeDigest());
        this.params = builder.params;
        if (this.params == null) {
            throw new NullPointerException("params == null");
        }
        int n = this.params.getTreeDigestSize();
        byte[] privateKey = builder.privateKey;
        if (privateKey == null) {
            this.index = builder.index;
            byte[] tmpSecretKeySeed = builder.secretKeySeed;
            if (tmpSecretKeySeed == null) {
                this.secretKeySeed = new byte[n];
            } else if (tmpSecretKeySeed.length != n) {
                throw new IllegalArgumentException("size of secretKeySeed needs to be equal size of digest");
            } else {
                this.secretKeySeed = tmpSecretKeySeed;
            }
            byte[] tmpSecretKeyPRF = builder.secretKeyPRF;
            if (tmpSecretKeyPRF == null) {
                this.secretKeyPRF = new byte[n];
            } else if (tmpSecretKeyPRF.length != n) {
                throw new IllegalArgumentException("size of secretKeyPRF needs to be equal size of digest");
            } else {
                this.secretKeyPRF = tmpSecretKeyPRF;
            }
            byte[] tmpPublicSeed = builder.publicSeed;
            if (tmpPublicSeed == null) {
                this.publicSeed = new byte[n];
            } else if (tmpPublicSeed.length != n) {
                throw new IllegalArgumentException("size of publicSeed needs to be equal size of digest");
            } else {
                this.publicSeed = tmpPublicSeed;
            }
            byte[] tmpRoot = builder.root;
            if (tmpRoot == null) {
                this.root = new byte[n];
            } else if (tmpRoot.length != n) {
                throw new IllegalArgumentException("size of root needs to be equal size of digest");
            } else {
                this.root = tmpRoot;
            }
            BDSStateMap tmpBDSState = builder.bdsState;
            if (tmpBDSState != null) {
                this.bdsState = tmpBDSState;
            } else {
                if (!XMSSUtil.isIndexValid(this.params.getHeight(), builder.index) || tmpPublicSeed == null || tmpSecretKeySeed == null) {
                    this.bdsState = new BDSStateMap(builder.maxIndex + 1);
                } else {
                    this.bdsState = new BDSStateMap(this.params, builder.index, tmpPublicSeed, tmpSecretKeySeed);
                }
            }
            if (builder.maxIndex >= 0 && builder.maxIndex != this.bdsState.getMaxIndex()) {
                throw new IllegalArgumentException("maxIndex set but not reflected in state");
            }
        } else if (builder.xmss == null) {
            throw new NullPointerException("xmss == null");
        } else {
            int totalHeight = this.params.getHeight();
            int indexSize = (totalHeight + 7) / 8;
            this.index = XMSSUtil.bytesToXBigEndian(privateKey, 0, indexSize);
            if (!XMSSUtil.isIndexValid(totalHeight, this.index)) {
                throw new IllegalArgumentException("index out of bounds");
            }
            int position = 0 + indexSize;
            this.secretKeySeed = XMSSUtil.extractBytesAtOffset(privateKey, position, n);
            int position2 = position + n;
            this.secretKeyPRF = XMSSUtil.extractBytesAtOffset(privateKey, position2, n);
            int position3 = position2 + n;
            this.publicSeed = XMSSUtil.extractBytesAtOffset(privateKey, position3, n);
            int position4 = position3 + n;
            this.root = XMSSUtil.extractBytesAtOffset(privateKey, position4, n);
            int position5 = position4 + n;
            try {
                this.bdsState = ((BDSStateMap) XMSSUtil.deserialize(XMSSUtil.extractBytesAtOffset(privateKey, position5, privateKey.length - position5), BDSStateMap.class)).withWOTSDigest(builder.xmss.getTreeDigestOID());
            } catch (IOException e) {
                throw new IllegalArgumentException(e.getMessage(), e);
            } catch (ClassNotFoundException e2) {
                throw new IllegalArgumentException(e2.getMessage(), e2);
            }
        }
    }

    @Override // com.mi.car.jsse.easysec.util.Encodable
    public byte[] getEncoded() throws IOException {
        byte[] byteArray;
        synchronized (this) {
            byteArray = toByteArray();
        }
        return byteArray;
    }

    public static class Builder {
        private BDSStateMap bdsState = null;
        private long index = 0;
        private long maxIndex = -1;
        private final XMSSMTParameters params;
        private byte[] privateKey = null;
        private byte[] publicSeed = null;
        private byte[] root = null;
        private byte[] secretKeyPRF = null;
        private byte[] secretKeySeed = null;
        private XMSSParameters xmss = null;

        public Builder(XMSSMTParameters params2) {
            this.params = params2;
        }

        public Builder withIndex(long val) {
            this.index = val;
            return this;
        }

        public Builder withMaxIndex(long val) {
            this.maxIndex = val;
            return this;
        }

        public Builder withSecretKeySeed(byte[] val) {
            this.secretKeySeed = XMSSUtil.cloneArray(val);
            return this;
        }

        public Builder withSecretKeyPRF(byte[] val) {
            this.secretKeyPRF = XMSSUtil.cloneArray(val);
            return this;
        }

        public Builder withPublicSeed(byte[] val) {
            this.publicSeed = XMSSUtil.cloneArray(val);
            return this;
        }

        public Builder withRoot(byte[] val) {
            this.root = XMSSUtil.cloneArray(val);
            return this;
        }

        public Builder withBDSState(BDSStateMap val) {
            if (val.getMaxIndex() == 0) {
                this.bdsState = new BDSStateMap(val, (1 << this.params.getHeight()) - 1);
            } else {
                this.bdsState = val;
            }
            return this;
        }

        public Builder withPrivateKey(byte[] privateKeyVal) {
            this.privateKey = XMSSUtil.cloneArray(privateKeyVal);
            this.xmss = this.params.getXMSSParameters();
            return this;
        }

        public XMSSMTPrivateKeyParameters build() {
            return new XMSSMTPrivateKeyParameters(this);
        }
    }

    @Override // com.mi.car.jsse.easysec.pqc.crypto.xmss.XMSSStoreableObjectInterface
    public byte[] toByteArray() {
        byte[] concatenate;
        synchronized (this) {
            int n = this.params.getTreeDigestSize();
            int indexSize = (this.params.getHeight() + 7) / 8;
            byte[] out = new byte[(indexSize + n + n + n + n)];
            XMSSUtil.copyBytesAtOffset(out, XMSSUtil.toBytesBigEndian(this.index, indexSize), 0);
            int position = 0 + indexSize;
            XMSSUtil.copyBytesAtOffset(out, this.secretKeySeed, position);
            int position2 = position + n;
            XMSSUtil.copyBytesAtOffset(out, this.secretKeyPRF, position2);
            int position3 = position2 + n;
            XMSSUtil.copyBytesAtOffset(out, this.publicSeed, position3);
            XMSSUtil.copyBytesAtOffset(out, this.root, position3 + n);
            try {
                concatenate = Arrays.concatenate(out, XMSSUtil.serialize(this.bdsState));
            } catch (IOException e) {
                throw new IllegalStateException("error serializing bds state: " + e.getMessage(), e);
            }
        }
        return concatenate;
    }

    public long getIndex() {
        return this.index;
    }

    public long getUsagesRemaining() {
        long maxIndex;
        synchronized (this) {
            maxIndex = (this.bdsState.getMaxIndex() - getIndex()) + 1;
        }
        return maxIndex;
    }

    public byte[] getSecretKeySeed() {
        return XMSSUtil.cloneArray(this.secretKeySeed);
    }

    public byte[] getSecretKeyPRF() {
        return XMSSUtil.cloneArray(this.secretKeyPRF);
    }

    public byte[] getPublicSeed() {
        return XMSSUtil.cloneArray(this.publicSeed);
    }

    public byte[] getRoot() {
        return XMSSUtil.cloneArray(this.root);
    }

    /* access modifiers changed from: package-private */
    public BDSStateMap getBDSState() {
        return this.bdsState;
    }

    public XMSSMTParameters getParameters() {
        return this.params;
    }

    public XMSSMTPrivateKeyParameters getNextKey() {
        XMSSMTPrivateKeyParameters extractKeyShard;
        synchronized (this) {
            extractKeyShard = extractKeyShard(1);
        }
        return extractKeyShard;
    }

    /* access modifiers changed from: package-private */
    public XMSSMTPrivateKeyParameters rollKey() {
        synchronized (this) {
            if (getIndex() < this.bdsState.getMaxIndex()) {
                this.bdsState.updateState(this.params, this.index, this.publicSeed, this.secretKeySeed);
                this.index++;
                this.used = false;
            } else {
                this.index = this.bdsState.getMaxIndex() + 1;
                this.bdsState = new BDSStateMap(this.bdsState.getMaxIndex());
                this.used = false;
            }
        }
        return this;
    }

    public XMSSMTPrivateKeyParameters extractKeyShard(int usageCount) {
        XMSSMTPrivateKeyParameters keyParams;
        if (usageCount < 1) {
            throw new IllegalArgumentException("cannot ask for a shard with 0 keys");
        }
        synchronized (this) {
            if (((long) usageCount) <= getUsagesRemaining()) {
                keyParams = new Builder(this.params).withSecretKeySeed(this.secretKeySeed).withSecretKeyPRF(this.secretKeyPRF).withPublicSeed(this.publicSeed).withRoot(this.root).withIndex(getIndex()).withBDSState(new BDSStateMap(this.bdsState, (getIndex() + ((long) usageCount)) - 1)).build();
                for (int i = 0; i != usageCount; i++) {
                    rollKey();
                }
            } else {
                throw new IllegalArgumentException("usageCount exceeds usages remaining");
            }
        }
        return keyParams;
    }
}
