package com.mi.car.jsse.easysec.pqc.crypto.sphincsplus;

import com.mi.car.jsse.easysec.util.Arrays;
import java.util.LinkedList;

class HT {
    SPHINCSPlusEngine engine;
    final byte[] htPubKey;
    private final byte[] pkSeed;
    private final byte[] skSeed;
    WotsPlus wots;

    public HT(SPHINCSPlusEngine engine2, byte[] skSeed2, byte[] pkSeed2) {
        this.skSeed = skSeed2;
        this.pkSeed = pkSeed2;
        this.engine = engine2;
        this.wots = new WotsPlus(engine2);
        ADRS adrs = new ADRS();
        adrs.setLayerAddress(engine2.D - 1);
        adrs.setTreeAddress(0);
        if (skSeed2 != null) {
            this.htPubKey = xmss_PKgen(skSeed2, pkSeed2, adrs);
        } else {
            this.htPubKey = null;
        }
    }

    /* access modifiers changed from: package-private */
    public byte[] sign(byte[] M, long idx_tree, int idx_leaf) {
        ADRS adrs = new ADRS();
        adrs.setLayerAddress(0);
        adrs.setTreeAddress(idx_tree);
        SIG_XMSS SIG_tmp = xmss_sign(M, this.skSeed, idx_leaf, this.pkSeed, adrs);
        SIG_XMSS[] SIG_HT = new SIG_XMSS[this.engine.D];
        SIG_HT[0] = SIG_tmp;
        adrs.setLayerAddress(0);
        adrs.setTreeAddress(idx_tree);
        byte[] root = xmss_pkFromSig(idx_leaf, SIG_tmp, M, this.pkSeed, adrs);
        for (int j = 1; j < this.engine.D; j++) {
            int idx_leaf2 = (int) (((long) ((1 << this.engine.H_PRIME) - 1)) & idx_tree);
            idx_tree >>>= this.engine.H_PRIME;
            adrs.setLayerAddress(j);
            adrs.setTreeAddress(idx_tree);
            SIG_XMSS SIG_tmp2 = xmss_sign(root, this.skSeed, idx_leaf2, this.pkSeed, adrs);
            SIG_HT[j] = SIG_tmp2;
            if (j < this.engine.D - 1) {
                root = xmss_pkFromSig(idx_leaf2, SIG_tmp2, root, this.pkSeed, adrs);
            }
        }
        byte[][] totSigs = new byte[SIG_HT.length][];
        for (int i = 0; i != totSigs.length; i++) {
            totSigs[i] = Arrays.concatenate(SIG_HT[i].sig, Arrays.concatenate(SIG_HT[i].auth));
        }
        return Arrays.concatenate(totSigs);
    }

    /* access modifiers changed from: package-private */
    public byte[] xmss_PKgen(byte[] skSeed2, byte[] pkSeed2, ADRS adrs) {
        return treehash(skSeed2, 0, this.engine.H_PRIME, pkSeed2, adrs);
    }

    /* access modifiers changed from: package-private */
    public byte[] xmss_pkFromSig(int idx, SIG_XMSS sig_xmss, byte[] M, byte[] pkSeed2, ADRS paramAdrs) {
        byte[] node1;
        ADRS adrs = new ADRS(paramAdrs);
        adrs.setType(0);
        adrs.setKeyPairAddress(idx);
        byte[] sig = sig_xmss.getWOTSSig();
        byte[][] AUTH = sig_xmss.getXMSSAUTH();
        byte[] node0 = this.wots.pkFromSig(sig, M, pkSeed2, adrs);
        adrs.setType(2);
        adrs.setTreeIndex(idx);
        for (int k = 0; k < this.engine.H_PRIME; k++) {
            adrs.setTreeHeight(k + 1);
            if ((idx / (1 << k)) % 2 == 0) {
                adrs.setTreeIndex(adrs.getTreeIndex() / 2);
                node1 = this.engine.H(pkSeed2, adrs, node0, AUTH[k]);
            } else {
                adrs.setTreeIndex((adrs.getTreeIndex() - 1) / 2);
                node1 = this.engine.H(pkSeed2, adrs, AUTH[k], node0);
            }
            node0 = node1;
        }
        return node0;
    }

    /* access modifiers changed from: package-private */
    public SIG_XMSS xmss_sign(byte[] M, byte[] skSeed2, int idx, byte[] pkSeed2, ADRS adrs) {
        byte[][] AUTH = new byte[this.engine.H_PRIME][];
        for (int j = 0; j < this.engine.H_PRIME; j++) {
            AUTH[j] = treehash(skSeed2, ((idx / (1 << j)) ^ 1) * (1 << j), j, pkSeed2, adrs);
        }
        ADRS adrs2 = new ADRS(adrs);
        adrs2.setType(0);
        adrs2.setKeyPairAddress(idx);
        return new SIG_XMSS(this.wots.sign(M, skSeed2, pkSeed2, adrs2), AUTH);
    }

    /* access modifiers changed from: package-private */
    public byte[] treehash(byte[] skSeed2, int s, int z, byte[] pkSeed2, ADRS adrsParam) {
        ADRS adrs = new ADRS(adrsParam);
        LinkedList<NodeEntry> stack = new LinkedList<>();
        if (s % (1 << z) != 0) {
            return null;
        }
        for (int idx = 0; idx < (1 << z); idx++) {
            adrs.setType(0);
            adrs.setKeyPairAddress(s + idx);
            byte[] node = this.wots.pkGen(skSeed2, pkSeed2, adrs);
            adrs.setType(2);
            adrs.setTreeHeight(1);
            adrs.setTreeIndex(s + idx);
            while (!stack.isEmpty() && stack.get(0).nodeHeight == adrs.getTreeHeight()) {
                adrs.setTreeIndex((adrs.getTreeIndex() - 1) / 2);
                node = this.engine.H(pkSeed2, adrs, stack.remove(0).nodeValue, node);
                adrs.setTreeHeight(adrs.getTreeHeight() + 1);
            }
            stack.add(0, new NodeEntry(node, adrs.getTreeHeight()));
        }
        return stack.get(0).nodeValue;
    }

    public boolean verify(byte[] M, SIG_XMSS[] sig_ht, byte[] pkSeed2, long idx_tree, int idx_leaf, byte[] PK_HT) {
        ADRS adrs = new ADRS();
        SIG_XMSS SIG_tmp = sig_ht[0];
        adrs.setLayerAddress(0);
        adrs.setTreeAddress(idx_tree);
        byte[] node = xmss_pkFromSig(idx_leaf, SIG_tmp, M, pkSeed2, adrs);
        for (int j = 1; j < this.engine.D; j++) {
            int idx_leaf2 = (int) (((long) ((1 << this.engine.H_PRIME) - 1)) & idx_tree);
            idx_tree >>>= this.engine.H_PRIME;
            SIG_XMSS SIG_tmp2 = sig_ht[j];
            adrs.setLayerAddress(j);
            adrs.setTreeAddress(idx_tree);
            node = xmss_pkFromSig(idx_leaf2, SIG_tmp2, node, pkSeed2, adrs);
        }
        return Arrays.areEqual(PK_HT, node);
    }
}
