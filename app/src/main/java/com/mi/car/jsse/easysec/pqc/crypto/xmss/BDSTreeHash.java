package com.mi.car.jsse.easysec.pqc.crypto.xmss;

import com.mi.car.jsse.easysec.pqc.crypto.xmss.HashTreeAddress;
import com.mi.car.jsse.easysec.pqc.crypto.xmss.LTreeAddress;
import com.mi.car.jsse.easysec.pqc.crypto.xmss.OTSHashAddress;
import java.io.Serializable;
import java.util.Stack;

/* access modifiers changed from: package-private */
public class BDSTreeHash implements Serializable, Cloneable {
    private static final long serialVersionUID = 1;
    private boolean finished = false;
    private int height;
    private final int initialHeight;
    private boolean initialized = false;
    private int nextIndex;
    private XMSSNode tailNode;

    BDSTreeHash(int initialHeight2) {
        this.initialHeight = initialHeight2;
    }

    /* access modifiers changed from: package-private */
    public void initialize(int nextIndex2) {
        this.tailNode = null;
        this.height = this.initialHeight;
        this.nextIndex = nextIndex2;
        this.initialized = true;
        this.finished = false;
    }

    /* access modifiers changed from: package-private */
    public void update(Stack<XMSSNode> stack, WOTSPlus wotsPlus, byte[] publicSeed, byte[] secretSeed, OTSHashAddress otsHashAddress) {
        if (otsHashAddress == null) {
            throw new NullPointerException("otsHashAddress == null");
        } else if (this.finished || !this.initialized) {
            throw new IllegalStateException("finished or not initialized");
        } else {
            OTSHashAddress otsHashAddress2 = (OTSHashAddress) ((OTSHashAddress.Builder) ((OTSHashAddress.Builder) ((OTSHashAddress.Builder) new OTSHashAddress.Builder().withLayerAddress(otsHashAddress.getLayerAddress())).withTreeAddress(otsHashAddress.getTreeAddress())).withOTSAddress(this.nextIndex).withChainAddress(otsHashAddress.getChainAddress()).withHashAddress(otsHashAddress.getHashAddress()).withKeyAndMask(otsHashAddress.getKeyAndMask())).build();
            HashTreeAddress hashTreeAddress = (HashTreeAddress) ((HashTreeAddress.Builder) ((HashTreeAddress.Builder) new HashTreeAddress.Builder().withLayerAddress(otsHashAddress2.getLayerAddress())).withTreeAddress(otsHashAddress2.getTreeAddress())).withTreeIndex(this.nextIndex).build();
            wotsPlus.importKeys(wotsPlus.getWOTSPlusSecretKey(secretSeed, otsHashAddress2), publicSeed);
            XMSSNode node = XMSSNodeUtil.lTree(wotsPlus, wotsPlus.getPublicKey(otsHashAddress2), (LTreeAddress) ((LTreeAddress.Builder) ((LTreeAddress.Builder) new LTreeAddress.Builder().withLayerAddress(otsHashAddress2.getLayerAddress())).withTreeAddress(otsHashAddress2.getTreeAddress())).withLTreeAddress(this.nextIndex).build());
            while (!stack.isEmpty() && stack.peek().getHeight() == node.getHeight() && stack.peek().getHeight() != this.initialHeight) {
                HashTreeAddress hashTreeAddress2 = (HashTreeAddress) ((HashTreeAddress.Builder) ((HashTreeAddress.Builder) ((HashTreeAddress.Builder) new HashTreeAddress.Builder().withLayerAddress(hashTreeAddress.getLayerAddress())).withTreeAddress(hashTreeAddress.getTreeAddress())).withTreeHeight(hashTreeAddress.getTreeHeight()).withTreeIndex((hashTreeAddress.getTreeIndex() - 1) / 2).withKeyAndMask(hashTreeAddress.getKeyAndMask())).build();
                XMSSNode node2 = XMSSNodeUtil.randomizeHash(wotsPlus, stack.pop(), node, hashTreeAddress2);
                XMSSNode node3 = new XMSSNode(node2.getHeight() + 1, node2.getValue());
                hashTreeAddress = (HashTreeAddress) ((HashTreeAddress.Builder) ((HashTreeAddress.Builder) ((HashTreeAddress.Builder) new HashTreeAddress.Builder().withLayerAddress(hashTreeAddress2.getLayerAddress())).withTreeAddress(hashTreeAddress2.getTreeAddress())).withTreeHeight(hashTreeAddress2.getTreeHeight() + 1).withTreeIndex(hashTreeAddress2.getTreeIndex()).withKeyAndMask(hashTreeAddress2.getKeyAndMask())).build();
                node = node3;
            }
            if (this.tailNode == null) {
                this.tailNode = node;
            } else if (this.tailNode.getHeight() == node.getHeight()) {
                HashTreeAddress hashTreeAddress3 = (HashTreeAddress) ((HashTreeAddress.Builder) ((HashTreeAddress.Builder) ((HashTreeAddress.Builder) new HashTreeAddress.Builder().withLayerAddress(hashTreeAddress.getLayerAddress())).withTreeAddress(hashTreeAddress.getTreeAddress())).withTreeHeight(hashTreeAddress.getTreeHeight()).withTreeIndex((hashTreeAddress.getTreeIndex() - 1) / 2).withKeyAndMask(hashTreeAddress.getKeyAndMask())).build();
                XMSSNode node4 = new XMSSNode(this.tailNode.getHeight() + 1, XMSSNodeUtil.randomizeHash(wotsPlus, this.tailNode, node, hashTreeAddress3).getValue());
                this.tailNode = node4;
                HashTreeAddress hashTreeAddress4 = (HashTreeAddress) ((HashTreeAddress.Builder) ((HashTreeAddress.Builder) ((HashTreeAddress.Builder) new HashTreeAddress.Builder().withLayerAddress(hashTreeAddress3.getLayerAddress())).withTreeAddress(hashTreeAddress3.getTreeAddress())).withTreeHeight(hashTreeAddress3.getTreeHeight() + 1).withTreeIndex(hashTreeAddress3.getTreeIndex()).withKeyAndMask(hashTreeAddress3.getKeyAndMask())).build();
                node = node4;
            } else {
                stack.push(node);
            }
            if (this.tailNode.getHeight() == this.initialHeight) {
                this.finished = true;
                return;
            }
            this.height = node.getHeight();
            this.nextIndex++;
        }
    }

    /* access modifiers changed from: package-private */
    public int getHeight() {
        if (!this.initialized || this.finished) {
            return Integer.MAX_VALUE;
        }
        return this.height;
    }

    /* access modifiers changed from: package-private */
    public int getIndexLeaf() {
        return this.nextIndex;
    }

    /* access modifiers changed from: package-private */
    public void setNode(XMSSNode node) {
        this.tailNode = node;
        this.height = node.getHeight();
        if (this.height == this.initialHeight) {
            this.finished = true;
        }
    }

    /* access modifiers changed from: package-private */
    public boolean isFinished() {
        return this.finished;
    }

    /* access modifiers changed from: package-private */
    public boolean isInitialized() {
        return this.initialized;
    }

    public XMSSNode getTailNode() {
        return this.tailNode;
    }

    /* access modifiers changed from: protected */
    @Override // java.lang.Object
    public BDSTreeHash clone() {
        BDSTreeHash th = new BDSTreeHash(this.initialHeight);
        th.tailNode = this.tailNode;
        th.height = this.height;
        th.nextIndex = this.nextIndex;
        th.initialized = this.initialized;
        th.finished = this.finished;
        return th;
    }
}
