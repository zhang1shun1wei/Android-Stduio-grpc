package com.mi.car.jsse.easysec.pqc.crypto.lms;

import com.mi.car.jsse.easysec.crypto.Digest;

public class LMSContext implements Digest {
    private final byte[] C;
    private volatile Digest digest;
    private final LMOtsPrivateKey key;
    private final byte[][] path;
    private final LMOtsPublicKey publicKey;
    private final LMSigParameters sigParams;
    private final Object signature;
    private LMSSignedPubKey[] signedPubKeys;

    public LMSContext(LMOtsPrivateKey key2, LMSigParameters sigParams2, Digest digest2, byte[] C2, byte[][] path2) {
        this.key = key2;
        this.sigParams = sigParams2;
        this.digest = digest2;
        this.C = C2;
        this.path = path2;
        this.publicKey = null;
        this.signature = null;
    }

    public LMSContext(LMOtsPublicKey publicKey2, Object signature2, Digest digest2) {
        this.publicKey = publicKey2;
        this.signature = signature2;
        this.digest = digest2;
        this.C = null;
        this.key = null;
        this.sigParams = null;
        this.path = null;
    }

    /* access modifiers changed from: package-private */
    public byte[] getC() {
        return this.C;
    }

    /* access modifiers changed from: package-private */
    public byte[] getQ() {
        byte[] Q = new byte[34];
        this.digest.doFinal(Q, 0);
        this.digest = null;
        return Q;
    }

    /* access modifiers changed from: package-private */
    public byte[][] getPath() {
        return this.path;
    }

    /* access modifiers changed from: package-private */
    public LMOtsPrivateKey getPrivateKey() {
        return this.key;
    }

    public LMOtsPublicKey getPublicKey() {
        return this.publicKey;
    }

    /* access modifiers changed from: package-private */
    public LMSigParameters getSigParams() {
        return this.sigParams;
    }

    public Object getSignature() {
        return this.signature;
    }

    /* access modifiers changed from: package-private */
    public LMSSignedPubKey[] getSignedPubKeys() {
        return this.signedPubKeys;
    }

    /* access modifiers changed from: package-private */
    public LMSContext withSignedPublicKeys(LMSSignedPubKey[] signedPubKeys2) {
        this.signedPubKeys = signedPubKeys2;
        return this;
    }

    @Override // com.mi.car.jsse.easysec.crypto.Digest
    public String getAlgorithmName() {
        return this.digest.getAlgorithmName();
    }

    @Override // com.mi.car.jsse.easysec.crypto.Digest
    public int getDigestSize() {
        return this.digest.getDigestSize();
    }

    @Override // com.mi.car.jsse.easysec.crypto.Digest
    public void update(byte in) {
        this.digest.update(in);
    }

    @Override // com.mi.car.jsse.easysec.crypto.Digest
    public void update(byte[] in, int inOff, int len) {
        this.digest.update(in, inOff, len);
    }

    @Override // com.mi.car.jsse.easysec.crypto.Digest
    public int doFinal(byte[] out, int outOff) {
        return this.digest.doFinal(out, outOff);
    }

    @Override // com.mi.car.jsse.easysec.crypto.Digest
    public void reset() {
        this.digest.reset();
    }
}
