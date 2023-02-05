package com.mi.car.jsse.easysec.pqc.crypto.xmss;

import com.mi.car.jsse.easysec.pqc.crypto.xmss.OTSHashAddress;
import com.mi.car.jsse.easysec.util.Arrays;
import com.mi.car.jsse.easysec.util.Encodable;
import com.mi.car.jsse.easysec.util.Pack;
import java.io.IOException;

public final class XMSSPrivateKeyParameters extends XMSSKeyParameters implements XMSSStoreableObjectInterface, Encodable {
    private volatile BDS bdsState;
    private final XMSSParameters params;
    private final byte[] publicSeed;
    private final byte[] root;
    private final byte[] secretKeyPRF;
    private final byte[] secretKeySeed;

    private XMSSPrivateKeyParameters(Builder builder) {
        super(true, builder.params.getTreeDigest());
        this.params = builder.params;
        if (this.params == null) {
            throw new NullPointerException("params == null");
        }
        int n = this.params.getTreeDigestSize();
        byte[] privateKey = builder.privateKey;
        if (privateKey != null) {
            int height = this.params.getHeight();
            int index = Pack.bigEndianToInt(privateKey, 0);
            if (!XMSSUtil.isIndexValid(height, (long) index)) {
                throw new IllegalArgumentException("index out of bounds");
            }
            this.secretKeySeed = XMSSUtil.extractBytesAtOffset(privateKey, 0 + 4, n);
            int position = n + 4;
            this.secretKeyPRF = XMSSUtil.extractBytesAtOffset(privateKey, position, n);
            int position2 = position + n;
            this.publicSeed = XMSSUtil.extractBytesAtOffset(privateKey, position2, n);
            int position3 = position2 + n;
            this.root = XMSSUtil.extractBytesAtOffset(privateKey, position3, n);
            int position4 = position3 + n;
            try {
                BDS bdsImport = (BDS) XMSSUtil.deserialize(XMSSUtil.extractBytesAtOffset(privateKey, position4, privateKey.length - position4), BDS.class);
                if (bdsImport.getIndex() != index) {
                    throw new IllegalStateException("serialized BDS has wrong index");
                }
                this.bdsState = bdsImport.withWOTSDigest(builder.params.getTreeDigestOID());
            } catch (IOException e) {
                throw new IllegalArgumentException(e.getMessage(), e);
            } catch (ClassNotFoundException e2) {
                throw new IllegalArgumentException(e2.getMessage(), e2);
            }
        } else {
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
            BDS tmpBDSState = builder.bdsState;
            if (tmpBDSState != null) {
                this.bdsState = tmpBDSState;
            } else if (builder.index >= (1 << this.params.getHeight()) - 2 || tmpPublicSeed == null || tmpSecretKeySeed == null) {
                this.bdsState = new BDS(this.params, (1 << this.params.getHeight()) - 1, builder.index);
            } else {
                this.bdsState = new BDS(this.params, tmpPublicSeed, tmpSecretKeySeed, (OTSHashAddress) new OTSHashAddress.Builder().build(), builder.index);
            }
            if (builder.maxIndex >= 0 && builder.maxIndex != this.bdsState.getMaxIndex()) {
                throw new IllegalArgumentException("maxIndex set but not reflected in state");
            }
        }
    }

    public long getUsagesRemaining() {
        long maxIndex;
        synchronized (this) {
            maxIndex = (long) ((this.bdsState.getMaxIndex() - getIndex()) + 1);
        }
        return maxIndex;
    }

    @Override // com.mi.car.jsse.easysec.util.Encodable
    public byte[] getEncoded() throws IOException {
        byte[] byteArray;
        synchronized (this) {
            byteArray = toByteArray();
        }
        return byteArray;
    }

    /* access modifiers changed from: package-private */
    public XMSSPrivateKeyParameters rollKey() {
        synchronized (this) {
            if (this.bdsState.getIndex() < this.bdsState.getMaxIndex()) {
                this.bdsState = this.bdsState.getNextState(this.publicSeed, this.secretKeySeed, (OTSHashAddress) new OTSHashAddress.Builder().build());
            } else {
                this.bdsState = new BDS(this.params, this.bdsState.getMaxIndex(), this.bdsState.getMaxIndex() + 1);
            }
        }
        return this;
    }

    public XMSSPrivateKeyParameters getNextKey() {
        XMSSPrivateKeyParameters keyParameters;
        synchronized (this) {
            keyParameters = extractKeyShard(1);
        }
        return keyParameters;
    }

    public XMSSPrivateKeyParameters extractKeyShard(int usageCount) {
        XMSSPrivateKeyParameters keyParams;
        if (usageCount < 1) {
            throw new IllegalArgumentException("cannot ask for a shard with 0 keys");
        }
        synchronized (this) {
            if (((long) usageCount) <= getUsagesRemaining()) {
                keyParams = new Builder(this.params).withSecretKeySeed(this.secretKeySeed).withSecretKeyPRF(this.secretKeyPRF).withPublicSeed(this.publicSeed).withRoot(this.root).withIndex(getIndex()).withBDSState(this.bdsState.withMaxIndex((this.bdsState.getIndex() + usageCount) - 1, this.params.getTreeDigestOID())).build();
                if (((long) usageCount) == getUsagesRemaining()) {
                    this.bdsState = new BDS(this.params, this.bdsState.getMaxIndex(), getIndex() + usageCount);
                } else {
                    OTSHashAddress hashAddress = (OTSHashAddress) new OTSHashAddress.Builder().build();
                    for (int i = 0; i != usageCount; i++) {
                        this.bdsState = this.bdsState.getNextState(this.publicSeed, this.secretKeySeed, hashAddress);
                    }
                }
            } else {
                throw new IllegalArgumentException("usageCount exceeds usages remaining");
            }
        }
        return keyParams;
    }

    public static class Builder {
        private BDS bdsState = null;
        private int index = 0;
        private int maxIndex = -1;
        private final XMSSParameters params;
        private byte[] privateKey = null;
        private byte[] publicSeed = null;
        private byte[] root = null;
        private byte[] secretKeyPRF = null;
        private byte[] secretKeySeed = null;

        public Builder(XMSSParameters params2) {
            this.params = params2;
        }

        public Builder withIndex(int val) {
            this.index = val;
            return this;
        }

        public Builder withMaxIndex(int val) {
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

        public Builder withBDSState(BDS valBDS) {
            this.bdsState = valBDS;
            return this;
        }

        public Builder withPrivateKey(byte[] privateKeyVal) {
            this.privateKey = XMSSUtil.cloneArray(privateKeyVal);
            return this;
        }

        public XMSSPrivateKeyParameters build() {
            return new XMSSPrivateKeyParameters(this);
        }
    }

    @Override // com.mi.car.jsse.easysec.pqc.crypto.xmss.XMSSStoreableObjectInterface
    public byte[] toByteArray() {
        byte[] concatenate;
        synchronized (this) {
            int n = this.params.getTreeDigestSize();
            byte[] out = new byte[(4 + n + n + n + n)];
            Pack.intToBigEndian(this.bdsState.getIndex(), out, 0);
            XMSSUtil.copyBytesAtOffset(out, this.secretKeySeed, 0 + 4);
            int position = n + 4;
            XMSSUtil.copyBytesAtOffset(out, this.secretKeyPRF, position);
            int position2 = position + n;
            XMSSUtil.copyBytesAtOffset(out, this.publicSeed, position2);
            XMSSUtil.copyBytesAtOffset(out, this.root, position2 + n);
            try {
                concatenate = Arrays.concatenate(out, XMSSUtil.serialize(this.bdsState));
            } catch (IOException e) {
                throw new RuntimeException("error serializing bds state: " + e.getMessage());
            }
        }
        return concatenate;
    }

    public int getIndex() {
        return this.bdsState.getIndex();
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
    public BDS getBDSState() {
        return this.bdsState;
    }

    public XMSSParameters getParameters() {
        return this.params;
    }
}
