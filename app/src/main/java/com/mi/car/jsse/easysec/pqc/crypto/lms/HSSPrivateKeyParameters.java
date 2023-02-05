package com.mi.car.jsse.easysec.pqc.crypto.lms;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

public class HSSPrivateKeyParameters extends LMSKeyParameters implements LMSContextBasedSigner {
    private long index = 0;
    private final long indexLimit;
    private final boolean isShard;
    private List<LMSPrivateKeyParameters> keys;
    private final int l;
    private HSSPublicKeyParameters publicKey;
    private List<LMSSignature> sig;

    public HSSPrivateKeyParameters(int l2, List<LMSPrivateKeyParameters> keys2, List<LMSSignature> sig2, long index2, long indexLimit2) {
        super(true);
        this.l = l2;
        this.keys = Collections.unmodifiableList(keys2);
        this.sig = Collections.unmodifiableList(sig2);
        this.index = index2;
        this.indexLimit = indexLimit2;
        this.isShard = false;
        resetKeyToIndex();
    }

    private HSSPrivateKeyParameters(int l2, List<LMSPrivateKeyParameters> keys2, List<LMSSignature> sig2, long index2, long indexLimit2, boolean isShard2) {
        super(true);
        this.l = l2;
        this.keys = Collections.unmodifiableList(keys2);
        this.sig = Collections.unmodifiableList(sig2);
        this.index = index2;
        this.indexLimit = indexLimit2;
        this.isShard = isShard2;
    }

    public static HSSPrivateKeyParameters getInstance(byte[] privEnc, byte[] pubEnc) throws IOException {
        HSSPrivateKeyParameters pKey = getInstance(privEnc);
        pKey.publicKey = HSSPublicKeyParameters.getInstance(pubEnc);
        return pKey;
    }

    /* JADX WARNING: Removed duplicated region for block: B:28:0x0085  */
    /* Code decompiled incorrectly, please refer to instructions dump. */
    public static HSSPrivateKeyParameters getInstance(Object r14) throws IOException {
        /*
        // Method dump skipped, instructions count: 181
        */
        throw new UnsupportedOperationException("Method not decompiled: com.mi.car.jsse.easysec.pqc.crypto.lms.HSSPrivateKeyParameters.getInstance(java.lang.Object):com.mi.car.jsse.easysec.pqc.crypto.lms.HSSPrivateKeyParameters");
    }

    public int getL() {
        return this.l;
    }

    public synchronized long getIndex() {
        return this.index;
    }

    public synchronized LMSParameters[] getLMSParameters() {
        LMSParameters[] parms;
        int len = this.keys.size();
        parms = new LMSParameters[len];
        for (int i = 0; i < len; i++) {
            LMSPrivateKeyParameters lmsPrivateKey = this.keys.get(i);
            parms[i] = new LMSParameters(lmsPrivateKey.getSigParameters(), lmsPrivateKey.getOtsParameters());
        }
        return parms;
    }

    /* access modifiers changed from: package-private */
    public synchronized void incIndex() {
        this.index++;
    }

    private static HSSPrivateKeyParameters makeCopy(HSSPrivateKeyParameters privateKeyParameters) {
        try {
            return getInstance(privateKeyParameters.getEncoded());
        } catch (Exception ex) {
            throw new RuntimeException(ex.getMessage(), ex);
        }
    }

    /* access modifiers changed from: protected */
    public void updateHierarchy(LMSPrivateKeyParameters[] newKeys, LMSSignature[] newSig) {
        synchronized (this) {
            this.keys = Collections.unmodifiableList(Arrays.asList(newKeys));
            this.sig = Collections.unmodifiableList(Arrays.asList(newSig));
        }
    }

    /* access modifiers changed from: package-private */
    public boolean isShard() {
        return this.isShard;
    }

    /* access modifiers changed from: package-private */
    public long getIndexLimit() {
        return this.indexLimit;
    }

    @Override // com.mi.car.jsse.easysec.pqc.crypto.lms.LMSContextBasedSigner
    public long getUsagesRemaining() {
        return this.indexLimit - this.index;
    }

    /* access modifiers changed from: package-private */
    public LMSPrivateKeyParameters getRootKey() {
        return this.keys.get(0);
    }

    public HSSPrivateKeyParameters extractKeyShard(int usageCount) {
        HSSPrivateKeyParameters shard;
        synchronized (this) {
            if (getUsagesRemaining() < ((long) usageCount)) {
                throw new IllegalArgumentException("usageCount exceeds usages remaining in current leaf");
            }
            long maxIndexForShard = this.index + ((long) usageCount);
            long shardStartIndex = this.index;
            this.index += (long) usageCount;
            shard = makeCopy(new HSSPrivateKeyParameters(this.l, new ArrayList<>(getKeys()), new ArrayList<>(getSig()), shardStartIndex, maxIndexForShard, true));
            resetKeyToIndex();
        }
        return shard;
    }

    /* access modifiers changed from: package-private */
    public synchronized List<LMSPrivateKeyParameters> getKeys() {
        return this.keys;
    }

    /* access modifiers changed from: package-private */
    public synchronized List<LMSSignature> getSig() {
        return this.sig;
    }

    /* access modifiers changed from: package-private */
    public void resetKeyToIndex() {
        List<LMSPrivateKeyParameters> originalKeys = getKeys();
        long[] qTreePath = new long[originalKeys.size()];
        long q = getIndex();
        for (int t = originalKeys.size() - 1; t >= 0; t--) {
            LMSigParameters sigParameters = originalKeys.get(t).getSigParameters();
            qTreePath[t] = ((long) ((1 << sigParameters.getH()) - 1)) & q;
            q >>>= sigParameters.getH();
        }
        boolean changed = false;
        LMSPrivateKeyParameters[] keys2 = (LMSPrivateKeyParameters[]) originalKeys.toArray(new LMSPrivateKeyParameters[originalKeys.size()]);
        LMSSignature[] sig2 = (LMSSignature[]) this.sig.toArray(new LMSSignature[this.sig.size()]);
        LMSPrivateKeyParameters originalRootKey = getRootKey();
        if (((long) (keys2[0].getIndex() - 1)) != qTreePath[0]) {
            keys2[0] = LMS.generateKeys(originalRootKey.getSigParameters(), originalRootKey.getOtsParameters(), (int) qTreePath[0], originalRootKey.getI(), originalRootKey.getMasterSecret());
            changed = true;
        }
        int i = 1;
        while (i < qTreePath.length) {
            LMSPrivateKeyParameters intermediateKey = keys2[i - 1];
            byte[] childI = new byte[16];
            byte[] childSeed = new byte[32];
            SeedDerive derive = new SeedDerive(intermediateKey.getI(), intermediateKey.getMasterSecret(), DigestUtil.getDigest(intermediateKey.getOtsParameters().getDigestOID()));
            derive.setQ((int) qTreePath[i - 1]);
            derive.setJ(-2);
            derive.deriveSeed(childSeed, true);
            byte[] postImage = new byte[32];
            derive.deriveSeed(postImage, false);
            System.arraycopy(postImage, 0, childI, 0, childI.length);
            boolean lmsQMatch = i < qTreePath.length + -1 ? qTreePath[i] == ((long) (keys2[i].getIndex() + -1)) : qTreePath[i] == ((long) keys2[i].getIndex());
            if (!(com.mi.car.jsse.easysec.util.Arrays.areEqual(childI, keys2[i].getI()) && com.mi.car.jsse.easysec.util.Arrays.areEqual(childSeed, keys2[i].getMasterSecret()))) {
                keys2[i] = LMS.generateKeys(originalKeys.get(i).getSigParameters(), originalKeys.get(i).getOtsParameters(), (int) qTreePath[i], childI, childSeed);
                sig2[i - 1] = LMS.generateSign(keys2[i - 1], keys2[i].getPublicKey().toByteArray());
                changed = true;
            } else if (!lmsQMatch) {
                keys2[i] = LMS.generateKeys(originalKeys.get(i).getSigParameters(), originalKeys.get(i).getOtsParameters(), (int) qTreePath[i], childI, childSeed);
                changed = true;
            }
            i++;
        }
        if (changed) {
            updateHierarchy(keys2, sig2);
        }
    }

    public synchronized HSSPublicKeyParameters getPublicKey() {
        return new HSSPublicKeyParameters(this.l, getRootKey().getPublicKey());
    }

    /* access modifiers changed from: package-private */
    public void replaceConsumedKey(int d) {
        SeedDerive deriver = this.keys.get(d - 1).getCurrentOTSKey().getDerivationFunction();
        deriver.setJ(-2);
        byte[] childRootSeed = new byte[32];
        deriver.deriveSeed(childRootSeed, true);
        byte[] postImage = new byte[32];
        deriver.deriveSeed(postImage, false);
        byte[] childI = new byte[16];
        System.arraycopy(postImage, 0, childI, 0, childI.length);
        List<LMSPrivateKeyParameters> newKeys = new ArrayList<>(this.keys);
        LMSPrivateKeyParameters oldPk = this.keys.get(d);
        newKeys.set(d, LMS.generateKeys(oldPk.getSigParameters(), oldPk.getOtsParameters(), 0, childI, childRootSeed));
        List<LMSSignature> newSig = new ArrayList<>(this.sig);
        newSig.set(d - 1, LMS.generateSign(newKeys.get(d - 1), newKeys.get(d).getPublicKey().toByteArray()));
        this.keys = Collections.unmodifiableList(newKeys);
        this.sig = Collections.unmodifiableList(newSig);
    }

    public boolean equals(Object o) {
        if (this == o) {
            return true;
        }
        if (o == null || getClass() != o.getClass()) {
            return false;
        }
        HSSPrivateKeyParameters that = (HSSPrivateKeyParameters) o;
        if (this.l == that.l && this.isShard == that.isShard && this.indexLimit == that.indexLimit && this.index == that.index && this.keys.equals(that.keys)) {
            return this.sig.equals(that.sig);
        }
        return false;
    }

    @Override // com.mi.car.jsse.easysec.util.Encodable, com.mi.car.jsse.easysec.pqc.crypto.lms.LMSKeyParameters
    public synchronized byte[] getEncoded() throws IOException {
        Composer composer;
        composer = Composer.compose().u32str(0).u32str(this.l).u64str(this.index).u64str(this.indexLimit).bool(this.isShard);
        for (LMSPrivateKeyParameters key : this.keys) {
            composer.bytes(key);
        }
        for (LMSSignature s : this.sig) {
            composer.bytes(s);
        }
        return composer.build();
    }

    public int hashCode() {
        return (((((((((this.l * 31) + (this.isShard ? 1 : 0)) * 31) + this.keys.hashCode()) * 31) + this.sig.hashCode()) * 31) + ((int) (this.indexLimit ^ (this.indexLimit >>> 32)))) * 31) + ((int) (this.index ^ (this.index >>> 32)));
    }

    /* access modifiers changed from: protected */
    public Object clone() throws CloneNotSupportedException {
        return makeCopy(this);
    }

    @Override // com.mi.car.jsse.easysec.pqc.crypto.lms.LMSContextBasedSigner
    public LMSContext generateLMSContext() {
        LMSPrivateKeyParameters nextKey;
        LMSSignedPubKey[] signed_pub_key;
        int L = getL();
        synchronized (this) {
            HSS.rangeTestKeys(this);
            List<LMSPrivateKeyParameters> keys2 = getKeys();
            List<LMSSignature> sig2 = getSig();
            nextKey = getKeys().get(L - 1);
            signed_pub_key = new LMSSignedPubKey[(L - 1)];
            for (int i = 0; i < L - 1; i++) {
                signed_pub_key[i] = new LMSSignedPubKey(sig2.get(i), keys2.get(i + 1).getPublicKey());
            }
            incIndex();
        }
        return nextKey.generateLMSContext().withSignedPublicKeys(signed_pub_key);
    }

    @Override // com.mi.car.jsse.easysec.pqc.crypto.lms.LMSContextBasedSigner
    public byte[] generateSignature(LMSContext context) {
        try {
            return HSS.generateSignature(getL(), context).getEncoded();
        } catch (IOException e) {
            throw new IllegalStateException("unable to encode signature: " + e.getMessage(), e);
        }
    }
}
