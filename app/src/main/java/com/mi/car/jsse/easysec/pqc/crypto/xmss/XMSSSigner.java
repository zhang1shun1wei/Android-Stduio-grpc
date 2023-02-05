package com.mi.car.jsse.easysec.pqc.crypto.xmss;

import com.mi.car.jsse.easysec.crypto.CipherParameters;
import com.mi.car.jsse.easysec.crypto.params.AsymmetricKeyParameter;
import com.mi.car.jsse.easysec.pqc.crypto.ExhaustedPrivateKeyException;
import com.mi.car.jsse.easysec.pqc.crypto.StateAwareMessageSigner;
import com.mi.car.jsse.easysec.pqc.crypto.xmss.OTSHashAddress;
import com.mi.car.jsse.easysec.pqc.crypto.xmss.XMSSSignature;
import com.mi.car.jsse.easysec.util.Arrays;

public class XMSSSigner implements StateAwareMessageSigner {
    private boolean hasGenerated;
    private boolean initSign;
    private KeyedHashFunctions khf;
    private XMSSParameters params;
    private XMSSPrivateKeyParameters privateKey;
    private XMSSPublicKeyParameters publicKey;
    private WOTSPlus wotsPlus;

    @Override // com.mi.car.jsse.easysec.pqc.crypto.MessageSigner
    public void init(boolean forSigning, CipherParameters param) {
        if (forSigning) {
            this.initSign = true;
            this.hasGenerated = false;
            this.privateKey = (XMSSPrivateKeyParameters) param;
            this.params = this.privateKey.getParameters();
        } else {
            this.initSign = false;
            this.publicKey = (XMSSPublicKeyParameters) param;
            this.params = this.publicKey.getParameters();
        }
        this.wotsPlus = this.params.getWOTSPlus();
        this.khf = this.wotsPlus.getKhf();
    }

    @Override // com.mi.car.jsse.easysec.pqc.crypto.MessageSigner
    public byte[] generateSignature(byte[] message) {
        byte[] byteArray;
        if (message == null) {
            throw new NullPointerException("message == null");
        } else if (!this.initSign) {
            throw new IllegalStateException("signer not initialized for signature generation");
        } else if (this.privateKey == null) {
            throw new IllegalStateException("signing key no longer usable");
        } else {
            synchronized (this.privateKey) {
                if (this.privateKey.getUsagesRemaining() <= 0) {
                    throw new ExhaustedPrivateKeyException("no usages of private key remaining");
                } else if (this.privateKey.getBDSState().getAuthenticationPath().isEmpty()) {
                    throw new IllegalStateException("not initialized");
                } else {
                    try {
                        int index = this.privateKey.getIndex();
                        this.hasGenerated = true;
                        byte[] random = this.khf.PRF(this.privateKey.getSecretKeyPRF(), XMSSUtil.toBytesBigEndian((long) index, 32));
                        byteArray = new XMSSSignature.Builder(this.params).withIndex(index).withRandom(random).withWOTSPlusSignature(wotsSign(this.khf.HMsg(Arrays.concatenate(random, this.privateKey.getRoot(), XMSSUtil.toBytesBigEndian((long) index, this.params.getTreeDigestSize())), message), (OTSHashAddress) new OTSHashAddress.Builder().withOTSAddress(index).build())).withAuthPath(this.privateKey.getBDSState().getAuthenticationPath()).build().toByteArray();
                    } finally {
                        this.privateKey.getBDSState().markUsed();
                        this.privateKey.rollKey();
                    }
                }
            }
            return byteArray;
        }
    }

    public long getUsagesRemaining() {
        return this.privateKey.getUsagesRemaining();
    }

    @Override // com.mi.car.jsse.easysec.pqc.crypto.MessageSigner
    public boolean verifySignature(byte[] message, byte[] signature) {
        XMSSSignature sig = new XMSSSignature.Builder(this.params).withSignature(signature).build();
        int index = sig.getIndex();
        this.wotsPlus.importKeys(new byte[this.params.getTreeDigestSize()], this.publicKey.getPublicSeed());
        byte[] messageDigest = this.khf.HMsg(Arrays.concatenate(sig.getRandom(), this.publicKey.getRoot(), XMSSUtil.toBytesBigEndian((long) index, this.params.getTreeDigestSize())), message);
        int xmssHeight = this.params.getHeight();
        int indexLeaf = XMSSUtil.getLeafIndex((long) index, xmssHeight);
        return Arrays.constantTimeAreEqual(XMSSVerifierUtil.getRootNodeFromSignature(this.wotsPlus, xmssHeight, messageDigest, sig, (OTSHashAddress) new OTSHashAddress.Builder().withOTSAddress(index).build(), indexLeaf).getValue(), this.publicKey.getRoot());
    }

    @Override // com.mi.car.jsse.easysec.pqc.crypto.StateAwareMessageSigner
    public AsymmetricKeyParameter getUpdatedPrivateKey() {
        synchronized (this.privateKey) {
            if (this.hasGenerated) {
                XMSSPrivateKeyParameters privKey = this.privateKey;
                this.privateKey = null;
                return privKey;
            }
            XMSSPrivateKeyParameters privKey2 = this.privateKey;
            if (privKey2 != null) {
                this.privateKey = this.privateKey.getNextKey();
            }
            return privKey2;
        }
    }

    private WOTSPlusSignature wotsSign(byte[] messageDigest, OTSHashAddress otsHashAddress) {
        if (messageDigest.length != this.params.getTreeDigestSize()) {
            throw new IllegalArgumentException("size of messageDigest needs to be equal to size of digest");
        } else if (otsHashAddress == null) {
            throw new NullPointerException("otsHashAddress == null");
        } else {
            this.wotsPlus.importKeys(this.wotsPlus.getWOTSPlusSecretKey(this.privateKey.getSecretKeySeed(), otsHashAddress), this.privateKey.getPublicSeed());
            return this.wotsPlus.sign(messageDigest, otsHashAddress);
        }
    }
}
