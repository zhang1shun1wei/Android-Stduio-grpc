package com.mi.car.jsse.easysec.pqc.crypto.xmss;

import com.mi.car.jsse.easysec.asn1.ASN1ObjectIdentifier;
import com.mi.car.jsse.easysec.pqc.crypto.xmss.HashTreeAddress;
import com.mi.car.jsse.easysec.pqc.crypto.xmss.LTreeAddress;
import com.mi.car.jsse.easysec.pqc.crypto.xmss.OTSHashAddress;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.Serializable;
import java.util.ArrayList;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Stack;
import java.util.TreeMap;

public final class BDS implements Serializable {
    private static final long serialVersionUID = 1;
    private List<XMSSNode> authenticationPath;
    private int index;
    private int k;
    private Map<Integer, XMSSNode> keep;
    private transient int maxIndex;
    private Map<Integer, LinkedList<XMSSNode>> retain;
    private XMSSNode root;
    private Stack<XMSSNode> stack;
    private final List<BDSTreeHash> treeHashInstances;
    private final int treeHeight;
    private boolean used;
    private transient WOTSPlus wotsPlus;

    BDS(XMSSParameters params, int maxIndex2, int index2) {
        this(params.getWOTSPlus(), params.getHeight(), params.getK(), index2);
        this.maxIndex = maxIndex2;
        this.index = index2;
        this.used = true;
    }

    BDS(XMSSParameters params, byte[] publicSeed, byte[] secretKeySeed, OTSHashAddress otsHashAddress) {
        this(params.getWOTSPlus(), params.getHeight(), params.getK(), (1 << params.getHeight()) - 1);
        initialize(publicSeed, secretKeySeed, otsHashAddress);
    }

    BDS(XMSSParameters params, byte[] publicSeed, byte[] secretKeySeed, OTSHashAddress otsHashAddress, int index2) {
        this(params.getWOTSPlus(), params.getHeight(), params.getK(), (1 << params.getHeight()) - 1);
        initialize(publicSeed, secretKeySeed, otsHashAddress);
        while (this.index < index2) {
            nextAuthenticationPath(publicSeed, secretKeySeed, otsHashAddress);
            this.used = false;
        }
    }

    private BDS(WOTSPlus wotsPlus2, int treeHeight2, int k2, int maxIndex2) {
        this.wotsPlus = wotsPlus2;
        this.treeHeight = treeHeight2;
        this.maxIndex = maxIndex2;
        this.k = k2;
        if (k2 > treeHeight2 || k2 < 2 || (treeHeight2 - k2) % 2 != 0) {
            throw new IllegalArgumentException("illegal value for BDS parameter k");
        }
        this.authenticationPath = new ArrayList();
        this.retain = new TreeMap();
        this.stack = new Stack<>();
        this.treeHashInstances = new ArrayList();
        for (int height = 0; height < treeHeight2 - k2; height++) {
            this.treeHashInstances.add(new BDSTreeHash(height));
        }
        this.keep = new TreeMap();
        this.index = 0;
        this.used = false;
    }

    BDS(BDS last) {
        this.wotsPlus = new WOTSPlus(last.wotsPlus.getParams());
        this.treeHeight = last.treeHeight;
        this.k = last.k;
        this.root = last.root;
        this.authenticationPath = new ArrayList();
        this.authenticationPath.addAll(last.authenticationPath);
        this.retain = new TreeMap();
        for (Integer key : last.retain.keySet()) {
            this.retain.put(key, (LinkedList) last.retain.get(key).clone());
        }
        this.stack = new Stack<>();
        this.stack.addAll(last.stack);
        this.treeHashInstances = new ArrayList();
        for (BDSTreeHash bDSTreeHash : last.treeHashInstances) {
            this.treeHashInstances.add(bDSTreeHash.clone());
        }
        this.keep = new TreeMap(last.keep);
        this.index = last.index;
        this.maxIndex = last.maxIndex;
        this.used = last.used;
    }

    private BDS(BDS last, byte[] publicSeed, byte[] secretKeySeed, OTSHashAddress otsHashAddress) {
        this.wotsPlus = new WOTSPlus(last.wotsPlus.getParams());
        this.treeHeight = last.treeHeight;
        this.k = last.k;
        this.root = last.root;
        this.authenticationPath = new ArrayList();
        this.authenticationPath.addAll(last.authenticationPath);
        this.retain = new TreeMap();
        for (Integer key : last.retain.keySet()) {
            this.retain.put(key, (LinkedList) last.retain.get(key).clone());
        }
        this.stack = new Stack<>();
        this.stack.addAll(last.stack);
        this.treeHashInstances = new ArrayList();
        for (BDSTreeHash bDSTreeHash : last.treeHashInstances) {
            this.treeHashInstances.add(bDSTreeHash.clone());
        }
        this.keep = new TreeMap(last.keep);
        this.index = last.index;
        this.maxIndex = last.maxIndex;
        this.used = false;
        nextAuthenticationPath(publicSeed, secretKeySeed, otsHashAddress);
    }

    private BDS(BDS last, ASN1ObjectIdentifier digest) {
        this.wotsPlus = new WOTSPlus(new WOTSPlusParameters(digest));
        this.treeHeight = last.treeHeight;
        this.k = last.k;
        this.root = last.root;
        this.authenticationPath = new ArrayList();
        this.authenticationPath.addAll(last.authenticationPath);
        this.retain = new TreeMap();
        for (Integer key : last.retain.keySet()) {
            this.retain.put(key, (LinkedList) last.retain.get(key).clone());
        }
        this.stack = new Stack<>();
        this.stack.addAll(last.stack);
        this.treeHashInstances = new ArrayList();
        for (BDSTreeHash bDSTreeHash : last.treeHashInstances) {
            this.treeHashInstances.add(bDSTreeHash.clone());
        }
        this.keep = new TreeMap(last.keep);
        this.index = last.index;
        this.maxIndex = last.maxIndex;
        this.used = last.used;
        validate();
    }

    private BDS(BDS last, int maxIndex2, ASN1ObjectIdentifier digest) {
        this.wotsPlus = new WOTSPlus(new WOTSPlusParameters(digest));
        this.treeHeight = last.treeHeight;
        this.k = last.k;
        this.root = last.root;
        this.authenticationPath = new ArrayList();
        this.authenticationPath.addAll(last.authenticationPath);
        this.retain = new TreeMap();
        for (Integer key : last.retain.keySet()) {
            this.retain.put(key, (LinkedList) last.retain.get(key).clone());
        }
        this.stack = new Stack<>();
        this.stack.addAll(last.stack);
        this.treeHashInstances = new ArrayList();
        for (BDSTreeHash bDSTreeHash : last.treeHashInstances) {
            this.treeHashInstances.add(bDSTreeHash.clone());
        }
        this.keep = new TreeMap(last.keep);
        this.index = last.index;
        this.maxIndex = maxIndex2;
        this.used = last.used;
        validate();
    }

    public BDS getNextState(byte[] publicSeed, byte[] secretKeySeed, OTSHashAddress otsHashAddress) {
        return new BDS(this, publicSeed, secretKeySeed, otsHashAddress);
    }

    private void initialize(byte[] publicSeed, byte[] secretSeed, OTSHashAddress otsHashAddress) {
        if (otsHashAddress == null) {
            throw new NullPointerException("otsHashAddress == null");
        }
        LTreeAddress lTreeAddress = (LTreeAddress) ((LTreeAddress.Builder) ((LTreeAddress.Builder) new LTreeAddress.Builder().withLayerAddress(otsHashAddress.getLayerAddress())).withTreeAddress(otsHashAddress.getTreeAddress())).build();
        HashTreeAddress hashTreeAddress = (HashTreeAddress) ((HashTreeAddress.Builder) ((HashTreeAddress.Builder) new HashTreeAddress.Builder().withLayerAddress(otsHashAddress.getLayerAddress())).withTreeAddress(otsHashAddress.getTreeAddress())).build();
        for (int indexLeaf = 0; indexLeaf < (1 << this.treeHeight); indexLeaf++) {
            otsHashAddress = (OTSHashAddress) ((OTSHashAddress.Builder) ((OTSHashAddress.Builder) ((OTSHashAddress.Builder) new OTSHashAddress.Builder().withLayerAddress(otsHashAddress.getLayerAddress())).withTreeAddress(otsHashAddress.getTreeAddress())).withOTSAddress(indexLeaf).withChainAddress(otsHashAddress.getChainAddress()).withHashAddress(otsHashAddress.getHashAddress()).withKeyAndMask(otsHashAddress.getKeyAndMask())).build();
            this.wotsPlus.importKeys(this.wotsPlus.getWOTSPlusSecretKey(secretSeed, otsHashAddress), publicSeed);
            WOTSPlusPublicKeyParameters wotsPlusPublicKey = this.wotsPlus.getPublicKey(otsHashAddress);
            lTreeAddress = (LTreeAddress) ((LTreeAddress.Builder) ((LTreeAddress.Builder) ((LTreeAddress.Builder) new LTreeAddress.Builder().withLayerAddress(lTreeAddress.getLayerAddress())).withTreeAddress(lTreeAddress.getTreeAddress())).withLTreeAddress(indexLeaf).withTreeHeight(lTreeAddress.getTreeHeight()).withTreeIndex(lTreeAddress.getTreeIndex()).withKeyAndMask(lTreeAddress.getKeyAndMask())).build();
            XMSSNode node = XMSSNodeUtil.lTree(this.wotsPlus, wotsPlusPublicKey, lTreeAddress);
            hashTreeAddress = (HashTreeAddress) ((HashTreeAddress.Builder) ((HashTreeAddress.Builder) ((HashTreeAddress.Builder) new HashTreeAddress.Builder().withLayerAddress(hashTreeAddress.getLayerAddress())).withTreeAddress(hashTreeAddress.getTreeAddress())).withTreeIndex(indexLeaf).withKeyAndMask(hashTreeAddress.getKeyAndMask())).build();
            while (!this.stack.isEmpty() && this.stack.peek().getHeight() == node.getHeight()) {
                int indexOnHeight = indexLeaf / (1 << node.getHeight());
                if (indexOnHeight == 1) {
                    this.authenticationPath.add(node);
                }
                if (indexOnHeight == 3 && node.getHeight() < this.treeHeight - this.k) {
                    this.treeHashInstances.get(node.getHeight()).setNode(node);
                }
                if (indexOnHeight >= 3 && (indexOnHeight & 1) == 1 && node.getHeight() >= this.treeHeight - this.k && node.getHeight() <= this.treeHeight - 2) {
                    if (this.retain.get(Integer.valueOf(node.getHeight())) == null) {
                        LinkedList<XMSSNode> queue = new LinkedList<>();
                        queue.add(node);
                        this.retain.put(Integer.valueOf(node.getHeight()), queue);
                    } else {
                        this.retain.get(Integer.valueOf(node.getHeight())).add(node);
                    }
                }
                HashTreeAddress hashTreeAddress2 = (HashTreeAddress) ((HashTreeAddress.Builder) ((HashTreeAddress.Builder) ((HashTreeAddress.Builder) new HashTreeAddress.Builder().withLayerAddress(hashTreeAddress.getLayerAddress())).withTreeAddress(hashTreeAddress.getTreeAddress())).withTreeHeight(hashTreeAddress.getTreeHeight()).withTreeIndex((hashTreeAddress.getTreeIndex() - 1) / 2).withKeyAndMask(hashTreeAddress.getKeyAndMask())).build();
                XMSSNode node2 = XMSSNodeUtil.randomizeHash(this.wotsPlus, this.stack.pop(), node, hashTreeAddress2);
                XMSSNode node3 = new XMSSNode(node2.getHeight() + 1, node2.getValue());
                hashTreeAddress = (HashTreeAddress) ((HashTreeAddress.Builder) ((HashTreeAddress.Builder) ((HashTreeAddress.Builder) new HashTreeAddress.Builder().withLayerAddress(hashTreeAddress2.getLayerAddress())).withTreeAddress(hashTreeAddress2.getTreeAddress())).withTreeHeight(hashTreeAddress2.getTreeHeight() + 1).withTreeIndex(hashTreeAddress2.getTreeIndex()).withKeyAndMask(hashTreeAddress2.getKeyAndMask())).build();
                node = node3;
            }
            this.stack.push(node);
        }
        this.root = this.stack.pop();
    }

    private void nextAuthenticationPath(byte[] publicSeed, byte[] secretSeed, OTSHashAddress otsHashAddress) {
        if (otsHashAddress == null) {
            throw new NullPointerException("otsHashAddress == null");
        } else if (this.used) {
            throw new IllegalStateException("index already used");
        } else if (this.index > this.maxIndex - 1) {
            throw new IllegalStateException("index out of bounds");
        } else {
            int tau = XMSSUtil.calculateTau(this.index, this.treeHeight);
            if (((this.index >> (tau + 1)) & 1) == 0 && tau < this.treeHeight - 1) {
                this.keep.put(Integer.valueOf(tau), this.authenticationPath.get(tau));
            }
            LTreeAddress lTreeAddress = (LTreeAddress) ((LTreeAddress.Builder) ((LTreeAddress.Builder) new LTreeAddress.Builder().withLayerAddress(otsHashAddress.getLayerAddress())).withTreeAddress(otsHashAddress.getTreeAddress())).build();
            HashTreeAddress hashTreeAddress = (HashTreeAddress) ((HashTreeAddress.Builder) ((HashTreeAddress.Builder) new HashTreeAddress.Builder().withLayerAddress(otsHashAddress.getLayerAddress())).withTreeAddress(otsHashAddress.getTreeAddress())).build();
            if (tau == 0) {
                otsHashAddress = (OTSHashAddress) ((OTSHashAddress.Builder) ((OTSHashAddress.Builder) ((OTSHashAddress.Builder) new OTSHashAddress.Builder().withLayerAddress(otsHashAddress.getLayerAddress())).withTreeAddress(otsHashAddress.getTreeAddress())).withOTSAddress(this.index).withChainAddress(otsHashAddress.getChainAddress()).withHashAddress(otsHashAddress.getHashAddress()).withKeyAndMask(otsHashAddress.getKeyAndMask())).build();
                this.wotsPlus.importKeys(this.wotsPlus.getWOTSPlusSecretKey(secretSeed, otsHashAddress), publicSeed);
                this.authenticationPath.set(0, XMSSNodeUtil.lTree(this.wotsPlus, this.wotsPlus.getPublicKey(otsHashAddress), (LTreeAddress) ((LTreeAddress.Builder) ((LTreeAddress.Builder) ((LTreeAddress.Builder) new LTreeAddress.Builder().withLayerAddress(lTreeAddress.getLayerAddress())).withTreeAddress(lTreeAddress.getTreeAddress())).withLTreeAddress(this.index).withTreeHeight(lTreeAddress.getTreeHeight()).withTreeIndex(lTreeAddress.getTreeIndex()).withKeyAndMask(lTreeAddress.getKeyAndMask())).build()));
            } else {
                this.wotsPlus.importKeys(this.wotsPlus.getWOTSPlusSecretKey(secretSeed, otsHashAddress), publicSeed);
                XMSSNode node = XMSSNodeUtil.randomizeHash(this.wotsPlus, this.authenticationPath.get(tau - 1), this.keep.get(Integer.valueOf(tau - 1)), (HashTreeAddress) ((HashTreeAddress.Builder) ((HashTreeAddress.Builder) ((HashTreeAddress.Builder) new HashTreeAddress.Builder().withLayerAddress(hashTreeAddress.getLayerAddress())).withTreeAddress(hashTreeAddress.getTreeAddress())).withTreeHeight(tau - 1).withTreeIndex(this.index >> tau).withKeyAndMask(hashTreeAddress.getKeyAndMask())).build());
                this.authenticationPath.set(tau, new XMSSNode(node.getHeight() + 1, node.getValue()));
                this.keep.remove(Integer.valueOf(tau - 1));
                for (int height = 0; height < tau; height++) {
                    if (height < this.treeHeight - this.k) {
                        this.authenticationPath.set(height, this.treeHashInstances.get(height).getTailNode());
                    } else {
                        this.authenticationPath.set(height, this.retain.get(Integer.valueOf(height)).removeFirst());
                    }
                }
                int minHeight = Math.min(tau, this.treeHeight - this.k);
                for (int height2 = 0; height2 < minHeight; height2++) {
                    int startIndex = this.index + 1 + ((1 << height2) * 3);
                    if (startIndex < (1 << this.treeHeight)) {
                        this.treeHashInstances.get(height2).initialize(startIndex);
                    }
                }
            }
            for (int i = 0; i < ((this.treeHeight - this.k) >> 1); i++) {
                BDSTreeHash treeHash = getBDSTreeHashInstanceForUpdate();
                if (treeHash != null) {
                    treeHash.update(this.stack, this.wotsPlus, publicSeed, secretSeed, otsHashAddress);
                }
            }
            this.index++;
        }
    }

    /* access modifiers changed from: package-private */
    public boolean isUsed() {
        return this.used;
    }

    /* access modifiers changed from: package-private */
    public void markUsed() {
        this.used = true;
    }

    private BDSTreeHash getBDSTreeHashInstanceForUpdate() {
        BDSTreeHash ret = null;
        for (BDSTreeHash treeHash : this.treeHashInstances) {
            if (!treeHash.isFinished() && treeHash.isInitialized()) {
                if (ret == null) {
                    ret = treeHash;
                } else if (treeHash.getHeight() < ret.getHeight()) {
                    ret = treeHash;
                } else if (treeHash.getHeight() == ret.getHeight() && treeHash.getIndexLeaf() < ret.getIndexLeaf()) {
                    ret = treeHash;
                }
            }
        }
        return ret;
    }

    private void validate() {
        if (this.authenticationPath == null) {
            throw new IllegalStateException("authenticationPath == null");
        } else if (this.retain == null) {
            throw new IllegalStateException("retain == null");
        } else if (this.stack == null) {
            throw new IllegalStateException("stack == null");
        } else if (this.treeHashInstances == null) {
            throw new IllegalStateException("treeHashInstances == null");
        } else if (this.keep == null) {
            throw new IllegalStateException("keep == null");
        } else if (!XMSSUtil.isIndexValid(this.treeHeight, (long) this.index)) {
            throw new IllegalStateException("index in BDS state out of bounds");
        }
    }

    /* access modifiers changed from: protected */
    public int getTreeHeight() {
        return this.treeHeight;
    }

    /* access modifiers changed from: protected */
    public XMSSNode getRoot() {
        return this.root;
    }

    /* access modifiers changed from: protected */
    public List<XMSSNode> getAuthenticationPath() {
        List<XMSSNode> authenticationPath2 = new ArrayList<>();
        for (XMSSNode node : this.authenticationPath) {
            authenticationPath2.add(node);
        }
        return authenticationPath2;
    }

    /* access modifiers changed from: protected */
    public int getIndex() {
        return this.index;
    }

    public int getMaxIndex() {
        return this.maxIndex;
    }

    public BDS withWOTSDigest(ASN1ObjectIdentifier digestName) {
        return new BDS(this, digestName);
    }

    public BDS withMaxIndex(int maxIndex2, ASN1ObjectIdentifier digestName) {
        return new BDS(this, maxIndex2, digestName);
    }

    private void readObject(ObjectInputStream in) throws IOException, ClassNotFoundException {
        in.defaultReadObject();
        if (in.available() != 0) {
            this.maxIndex = in.readInt();
        } else {
            this.maxIndex = (1 << this.treeHeight) - 1;
        }
        if (this.maxIndex > (1 << this.treeHeight) - 1 || this.index > this.maxIndex + 1 || in.available() != 0) {
            throw new IOException("inconsistent BDS data detected");
        }
    }

    private void writeObject(ObjectOutputStream out) throws IOException {
        out.defaultWriteObject();
        out.writeInt(this.maxIndex);
    }
}
