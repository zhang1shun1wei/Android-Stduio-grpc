package com.mi.car.jsse.easysec.pqc.crypto.xmss;

import com.mi.car.jsse.easysec.crypto.CipherParameters;
import com.mi.car.jsse.easysec.crypto.params.AsymmetricKeyParameter;
import com.mi.car.jsse.easysec.pqc.crypto.StateAwareMessageSigner;
import com.mi.car.jsse.easysec.pqc.crypto.xmss.OTSHashAddress;
import com.mi.car.jsse.easysec.pqc.crypto.xmss.XMSSMTSignature;
import com.mi.car.jsse.easysec.pqc.crypto.xmss.XMSSReducedSignature;
import com.mi.car.jsse.easysec.util.Arrays;

public class XMSSMTSigner implements StateAwareMessageSigner {
    private boolean hasGenerated;
    private boolean initSign;
    private XMSSMTParameters params;
    private XMSSMTPrivateKeyParameters privateKey;
    private XMSSMTPublicKeyParameters publicKey;
    private WOTSPlus wotsPlus;
    private XMSSParameters xmssParams;

    @Override // com.mi.car.jsse.easysec.pqc.crypto.MessageSigner
    public void init(boolean forSigning, CipherParameters param) {
        if (forSigning) {
            this.initSign = true;
            this.hasGenerated = false;
            this.privateKey = (XMSSMTPrivateKeyParameters) param;
            this.params = this.privateKey.getParameters();
            this.xmssParams = this.params.getXMSSParameters();
        } else {
            this.initSign = false;
            this.publicKey = (XMSSMTPublicKeyParameters) param;
            this.params = this.publicKey.getParameters();
            this.xmssParams = this.params.getXMSSParameters();
        }
        this.wotsPlus = this.params.getWOTSPlus();
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
                    throw new IllegalStateException("no usages of private key remaining");
                } else if (this.privateKey.getBDSState().isEmpty()) {
                    throw new IllegalStateException("not initialized");
                } else {
                    try {
                        BDSStateMap bdsState = this.privateKey.getBDSState();
                        long globalIndex = this.privateKey.getIndex();
                        this.params.getHeight();
                        int xmssHeight = this.xmssParams.getHeight();
                        if (this.privateKey.getUsagesRemaining() <= 0) {
                            throw new IllegalStateException("index out of bounds");
                        }
                        byte[] random = this.wotsPlus.getKhf().PRF(this.privateKey.getSecretKeyPRF(), XMSSUtil.toBytesBigEndian(globalIndex, 32));
                        byte[] messageDigest = this.wotsPlus.getKhf().HMsg(Arrays.concatenate(random, this.privateKey.getRoot(), XMSSUtil.toBytesBigEndian(globalIndex, this.params.getTreeDigestSize())), message);
                        this.hasGenerated = true;
                        XMSSMTSignature signature = new XMSSMTSignature.Builder(this.params).withIndex(globalIndex).withRandom(random).build();
                        long indexTree = XMSSUtil.getTreeIndex(globalIndex, xmssHeight);
                        int indexLeaf = XMSSUtil.getLeafIndex(globalIndex, xmssHeight);
                        this.wotsPlus.importKeys(new byte[this.params.getTreeDigestSize()], this.privateKey.getPublicSeed());
                        OTSHashAddress otsHashAddress = (OTSHashAddress) ((OTSHashAddress.Builder) new OTSHashAddress.Builder().withTreeAddress(indexTree)).withOTSAddress(indexLeaf).build();
                        if (bdsState.get(0) == null || indexLeaf == 0) {
                            bdsState.put(0, new BDS(this.xmssParams, this.privateKey.getPublicSeed(), this.privateKey.getSecretKeySeed(), otsHashAddress));
                        }
                        signature.getReducedSignatures().add(new XMSSReducedSignature.Builder(this.xmssParams).withWOTSPlusSignature(wotsSign(messageDigest, otsHashAddress)).withAuthPath(bdsState.get(0).getAuthenticationPath()).build());
                        for (int layer = 1; layer < this.params.getLayers(); layer++) {
                            XMSSNode root = bdsState.get(layer - 1).getRoot();
                            int indexLeaf2 = XMSSUtil.getLeafIndex(indexTree, xmssHeight);
                            indexTree = XMSSUtil.getTreeIndex(indexTree, xmssHeight);
                            OTSHashAddress otsHashAddress2 = (OTSHashAddress) ((OTSHashAddress.Builder) ((OTSHashAddress.Builder) new OTSHashAddress.Builder().withLayerAddress(layer)).withTreeAddress(indexTree)).withOTSAddress(indexLeaf2).build();
                            WOTSPlusSignature wotsPlusSignature = wotsSign(root.getValue(), otsHashAddress2);
                            if (bdsState.get(layer) == null || XMSSUtil.isNewBDSInitNeeded(globalIndex, xmssHeight, layer)) {
                                bdsState.put(layer, new BDS(this.xmssParams, this.privateKey.getPublicSeed(), this.privateKey.getSecretKeySeed(), otsHashAddress2));
                            }
                            signature.getReducedSignatures().add(new XMSSReducedSignature.Builder(this.xmssParams).withWOTSPlusSignature(wotsPlusSignature).withAuthPath(bdsState.get(layer).getAuthenticationPath()).build());
                        }
                        byteArray = signature.toByteArray();
                    } finally {
                        this.privateKey.rollKey();
                    }
                }
            }
            return byteArray;
        }
    }

    @Override // com.mi.car.jsse.easysec.pqc.crypto.MessageSigner
    public boolean verifySignature(byte[] message, byte[] signature) {
        if (message == null) {
            throw new NullPointerException("message == null");
        } else if (signature == null) {
            throw new NullPointerException("signature == null");
        } else if (this.publicKey == null) {
            throw new NullPointerException("publicKey == null");
        } else {
            XMSSMTSignature sig = new XMSSMTSignature.Builder(this.params).withSignature(signature).build();
            byte[] messageDigest = this.wotsPlus.getKhf().HMsg(Arrays.concatenate(sig.getRandom(), this.publicKey.getRoot(), XMSSUtil.toBytesBigEndian(sig.getIndex(), this.params.getTreeDigestSize())), message);
            long globalIndex = sig.getIndex();
            int xmssHeight = this.xmssParams.getHeight();
            long indexTree = XMSSUtil.getTreeIndex(globalIndex, xmssHeight);
            int indexLeaf = XMSSUtil.getLeafIndex(globalIndex, xmssHeight);
            this.wotsPlus.importKeys(new byte[this.params.getTreeDigestSize()], this.publicKey.getPublicSeed());
            XMSSReducedSignature xmssMTSignature = sig.getReducedSignatures().get(0);
            XMSSNode rootNode = XMSSVerifierUtil.getRootNodeFromSignature(this.wotsPlus, xmssHeight, messageDigest, xmssMTSignature, (OTSHashAddress) ((OTSHashAddress.Builder) new OTSHashAddress.Builder().withTreeAddress(indexTree)).withOTSAddress(indexLeaf).build(), indexLeaf);
            for (int layer = 1; layer < this.params.getLayers(); layer++) {
                int indexLeaf2 = XMSSUtil.getLeafIndex(indexTree, xmssHeight);
                indexTree = XMSSUtil.getTreeIndex(indexTree, xmssHeight);
                rootNode = XMSSVerifierUtil.getRootNodeFromSignature(this.wotsPlus, xmssHeight, rootNode.getValue(), sig.getReducedSignatures().get(layer), (OTSHashAddress) ((OTSHashAddress.Builder) ((OTSHashAddress.Builder) new OTSHashAddress.Builder().withLayerAddress(layer)).withTreeAddress(indexTree)).withOTSAddress(indexLeaf2).build(), indexLeaf2);
            }
            return Arrays.constantTimeAreEqual(rootNode.getValue(), this.publicKey.getRoot());
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

    public long getUsagesRemaining() {
        return this.privateKey.getUsagesRemaining();
    }

    @Override // com.mi.car.jsse.easysec.pqc.crypto.StateAwareMessageSigner
    public AsymmetricKeyParameter getUpdatedPrivateKey() {
        if (this.hasGenerated) {
            XMSSMTPrivateKeyParameters privKey = this.privateKey;
            this.privateKey = null;
            return privKey;
        }
        XMSSMTPrivateKeyParameters privKey2 = this.privateKey;
        if (privKey2 != null) {
            this.privateKey = this.privateKey.getNextKey();
        }
        return privKey2;
    }
}
