package com.mi.car.jsse.easysec.pqc.crypto.xmss;

import com.mi.car.jsse.easysec.asn1.ASN1ObjectIdentifier;
import com.mi.car.jsse.easysec.pqc.crypto.xmss.OTSHashAddress;
import com.mi.car.jsse.easysec.util.Integers;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.Serializable;
import java.util.Map;
import java.util.TreeMap;

public class BDSStateMap implements Serializable {
    private static final long serialVersionUID = -3464451825208522308L;
    private final Map<Integer, BDS> bdsState = new TreeMap();
    private transient long maxIndex;

    BDSStateMap(long maxIndex2) {
        this.maxIndex = maxIndex2;
    }

    BDSStateMap(BDSStateMap stateMap, long maxIndex2) {
        for (Integer key : stateMap.bdsState.keySet()) {
            this.bdsState.put(key, new BDS(stateMap.bdsState.get(key)));
        }
        this.maxIndex = maxIndex2;
    }

    BDSStateMap(XMSSMTParameters params, long globalIndex, byte[] publicSeed, byte[] secretKeySeed) {
        this.maxIndex = (1 << params.getHeight()) - 1;
        for (long index = 0; index < globalIndex; index++) {
            updateState(params, index, publicSeed, secretKeySeed);
        }
    }

    public long getMaxIndex() {
        return this.maxIndex;
    }

    /* access modifiers changed from: package-private */
    public void updateState(XMSSMTParameters params, long globalIndex, byte[] publicSeed, byte[] secretKeySeed) {
        XMSSParameters xmssParams = params.getXMSSParameters();
        int xmssHeight = xmssParams.getHeight();
        long indexTree = XMSSUtil.getTreeIndex(globalIndex, xmssHeight);
        int indexLeaf = XMSSUtil.getLeafIndex(globalIndex, xmssHeight);
        OTSHashAddress otsHashAddress = (OTSHashAddress) ((OTSHashAddress.Builder) new OTSHashAddress.Builder().withTreeAddress(indexTree)).withOTSAddress(indexLeaf).build();
        if (indexLeaf < (1 << xmssHeight) - 1) {
            if (get(0) == null || indexLeaf == 0) {
                put(0, new BDS(xmssParams, publicSeed, secretKeySeed, otsHashAddress));
            }
            update(0, publicSeed, secretKeySeed, otsHashAddress);
        }
        for (int layer = 1; layer < params.getLayers(); layer++) {
            int indexLeaf2 = XMSSUtil.getLeafIndex(indexTree, xmssHeight);
            indexTree = XMSSUtil.getTreeIndex(indexTree, xmssHeight);
            OTSHashAddress otsHashAddress2 = (OTSHashAddress) ((OTSHashAddress.Builder) ((OTSHashAddress.Builder) new OTSHashAddress.Builder().withLayerAddress(layer)).withTreeAddress(indexTree)).withOTSAddress(indexLeaf2).build();
            if (this.bdsState.get(Integer.valueOf(layer)) == null || XMSSUtil.isNewBDSInitNeeded(globalIndex, xmssHeight, layer)) {
                this.bdsState.put(Integer.valueOf(layer), new BDS(xmssParams, publicSeed, secretKeySeed, otsHashAddress2));
            }
            if (indexLeaf2 < (1 << xmssHeight) - 1 && XMSSUtil.isNewAuthenticationPathNeeded(globalIndex, xmssHeight, layer)) {
                update(layer, publicSeed, secretKeySeed, otsHashAddress2);
            }
        }
    }

    public boolean isEmpty() {
        return this.bdsState.isEmpty();
    }

    /* access modifiers changed from: package-private */
    public BDS get(int index) {
        return this.bdsState.get(Integers.valueOf(index));
    }

    /* access modifiers changed from: package-private */
    public BDS update(int index, byte[] publicSeed, byte[] secretKeySeed, OTSHashAddress otsHashAddress) {
        return this.bdsState.put(Integers.valueOf(index), this.bdsState.get(Integers.valueOf(index)).getNextState(publicSeed, secretKeySeed, otsHashAddress));
    }

    /* access modifiers changed from: package-private */
    public void put(int index, BDS bds) {
        this.bdsState.put(Integers.valueOf(index), bds);
    }

    public BDSStateMap withWOTSDigest(ASN1ObjectIdentifier digestName) {
        BDSStateMap newStateMap = new BDSStateMap(this.maxIndex);
        for (Integer key : this.bdsState.keySet()) {
            newStateMap.bdsState.put(key, this.bdsState.get(key).withWOTSDigest(digestName));
        }
        return newStateMap;
    }

    private void readObject(ObjectInputStream in) throws IOException, ClassNotFoundException {
        in.defaultReadObject();
        if (in.available() != 0) {
            this.maxIndex = in.readLong();
        } else {
            this.maxIndex = 0;
        }
    }

    private void writeObject(ObjectOutputStream out) throws IOException {
        out.defaultWriteObject();
        out.writeLong(this.maxIndex);
    }
}
