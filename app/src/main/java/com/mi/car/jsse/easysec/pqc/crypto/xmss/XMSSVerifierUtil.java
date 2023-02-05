package com.mi.car.jsse.easysec.pqc.crypto.xmss;

import com.mi.car.jsse.easysec.pqc.crypto.xmss.HashTreeAddress;
import com.mi.car.jsse.easysec.pqc.crypto.xmss.LTreeAddress;

/* access modifiers changed from: package-private */
public class XMSSVerifierUtil {
    XMSSVerifierUtil() {
    }

    static XMSSNode getRootNodeFromSignature(WOTSPlus wotsPlus, int height, byte[] messageDigest, XMSSReducedSignature signature, OTSHashAddress otsHashAddress, int indexLeaf) {
        if (messageDigest.length != wotsPlus.getParams().getTreeDigestSize()) {
            throw new IllegalArgumentException("size of messageDigest needs to be equal to size of digest");
        } else if (signature == null) {
            throw new NullPointerException("signature == null");
        } else if (otsHashAddress == null) {
            throw new NullPointerException("otsHashAddress == null");
        } else {
            HashTreeAddress hashTreeAddress = (HashTreeAddress) ((HashTreeAddress.Builder) ((HashTreeAddress.Builder) new HashTreeAddress.Builder().withLayerAddress(otsHashAddress.getLayerAddress())).withTreeAddress(otsHashAddress.getTreeAddress())).withTreeIndex(otsHashAddress.getOTSAddress()).build();
            XMSSNode[] node = new XMSSNode[2];
            node[0] = XMSSNodeUtil.lTree(wotsPlus, wotsPlus.getPublicKeyFromSignature(messageDigest, signature.getWOTSPlusSignature(), otsHashAddress), (LTreeAddress) ((LTreeAddress.Builder) ((LTreeAddress.Builder) new LTreeAddress.Builder().withLayerAddress(otsHashAddress.getLayerAddress())).withTreeAddress(otsHashAddress.getTreeAddress())).withLTreeAddress(otsHashAddress.getOTSAddress()).build());
            for (int k = 0; k < height; k++) {
                HashTreeAddress hashTreeAddress2 = (HashTreeAddress) ((HashTreeAddress.Builder) ((HashTreeAddress.Builder) ((HashTreeAddress.Builder) new HashTreeAddress.Builder().withLayerAddress(hashTreeAddress.getLayerAddress())).withTreeAddress(hashTreeAddress.getTreeAddress())).withTreeHeight(k).withTreeIndex(hashTreeAddress.getTreeIndex()).withKeyAndMask(hashTreeAddress.getKeyAndMask())).build();
                if (Math.floor((double) (indexLeaf / (1 << k))) % 2.0d == 0.0d) {
                    hashTreeAddress = (HashTreeAddress) ((HashTreeAddress.Builder) ((HashTreeAddress.Builder) ((HashTreeAddress.Builder) new HashTreeAddress.Builder().withLayerAddress(hashTreeAddress2.getLayerAddress())).withTreeAddress(hashTreeAddress2.getTreeAddress())).withTreeHeight(hashTreeAddress2.getTreeHeight()).withTreeIndex(hashTreeAddress2.getTreeIndex() / 2).withKeyAndMask(hashTreeAddress2.getKeyAndMask())).build();
                    node[1] = XMSSNodeUtil.randomizeHash(wotsPlus, node[0], signature.getAuthPath().get(k), hashTreeAddress);
                    node[1] = new XMSSNode(node[1].getHeight() + 1, node[1].getValue());
                } else {
                    hashTreeAddress = (HashTreeAddress) ((HashTreeAddress.Builder) ((HashTreeAddress.Builder) ((HashTreeAddress.Builder) new HashTreeAddress.Builder().withLayerAddress(hashTreeAddress2.getLayerAddress())).withTreeAddress(hashTreeAddress2.getTreeAddress())).withTreeHeight(hashTreeAddress2.getTreeHeight()).withTreeIndex((hashTreeAddress2.getTreeIndex() - 1) / 2).withKeyAndMask(hashTreeAddress2.getKeyAndMask())).build();
                    node[1] = XMSSNodeUtil.randomizeHash(wotsPlus, signature.getAuthPath().get(k), node[0], hashTreeAddress);
                    node[1] = new XMSSNode(node[1].getHeight() + 1, node[1].getValue());
                }
                node[0] = node[1];
            }
            return node[0];
        }
    }
}
