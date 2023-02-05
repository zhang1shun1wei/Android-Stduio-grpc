package com.mi.car.jsse.easysec.pqc.crypto.sphincsplus;

import com.mi.car.jsse.easysec.util.Arrays;
import java.util.LinkedList;

class Fors {
    SPHINCSPlusEngine engine;

    public Fors(SPHINCSPlusEngine engine2) {
        this.engine = engine2;
    }

    /* access modifiers changed from: package-private */
    public byte[] treehash(byte[] skSeed, int s, int z, byte[] pkSeed, ADRS adrsParam) {
        ADRS adrs = new ADRS(adrsParam);
        LinkedList<NodeEntry> stack = new LinkedList<>();
        if (s % (1 << z) != 0) {
            return null;
        }
        for (int idx = 0; idx < (1 << z); idx++) {
            adrs.setTreeHeight(0);
            adrs.setTreeIndex(s + idx);
            byte[] node = this.engine.F(pkSeed, adrs, this.engine.PRF(pkSeed, skSeed, adrs));
            adrs.setTreeHeight(1);
            adrs.setTreeIndex(s + idx);
            while (!stack.isEmpty() && stack.get(0).nodeHeight == adrs.getTreeHeight()) {
                adrs.setTreeIndex((adrs.getTreeIndex() - 1) / 2);
                node = this.engine.H(pkSeed, adrs, stack.remove(0).nodeValue, node);
                adrs.setTreeHeight(adrs.getTreeHeight() + 1);
            }
            stack.add(0, new NodeEntry(node, adrs.getTreeHeight()));
        }
        return stack.get(0).nodeValue;
    }

    public SIG_FORS[] sign(byte[] md, byte[] skSeed, byte[] pkSeed, ADRS adrs) {
        int[] idxs = message_to_idxs(md, this.engine.K, this.engine.A);
        SIG_FORS[] sig_fors = new SIG_FORS[this.engine.K];
        int t = this.engine.T;
        for (int i = 0; i < this.engine.K; i++) {
            int idx = idxs[i];
            adrs.setTreeHeight(0);
            adrs.setTreeIndex((i * t) + idx);
            byte[] sk = this.engine.PRF(pkSeed, skSeed, adrs);
            byte[][] authPath = new byte[this.engine.A][];
            for (int j = 0; j < this.engine.A; j++) {
                authPath[j] = treehash(skSeed, (i * t) + ((1 << j) * ((idx / (1 << j)) ^ 1)), j, pkSeed, adrs);
            }
            sig_fors[i] = new SIG_FORS(sk, authPath);
        }
        return sig_fors;
    }

    public byte[] pkFromSig(SIG_FORS[] sig_fors, byte[] message, byte[] pkSeed, ADRS adrs) {
        byte[][] node = new byte[2][];
        byte[][] root = new byte[this.engine.K][];
        int t = this.engine.T;
        int[] idxs = message_to_idxs(message, this.engine.K, this.engine.A);
        for (int i = 0; i < this.engine.K; i++) {
            int idx = idxs[i];
            byte[] sk = sig_fors[i].getSK();
            adrs.setTreeHeight(0);
            adrs.setTreeIndex((i * t) + idx);
            node[0] = this.engine.F(pkSeed, adrs, sk);
            byte[][] authPath = sig_fors[i].getAuthPath();
            adrs.setTreeIndex((i * t) + idx);
            for (int j = 0; j < this.engine.A; j++) {
                adrs.setTreeHeight(j + 1);
                if ((idx / (1 << j)) % 2 == 0) {
                    adrs.setTreeIndex(adrs.getTreeIndex() / 2);
                    node[1] = this.engine.H(pkSeed, adrs, node[0], authPath[j]);
                } else {
                    adrs.setTreeIndex((adrs.getTreeIndex() - 1) / 2);
                    node[1] = this.engine.H(pkSeed, adrs, authPath[j], node[0]);
                }
                node[0] = node[1];
            }
            root[i] = node[0];
        }
        ADRS forspkADRS = new ADRS(adrs);
        forspkADRS.setType(4);
        forspkADRS.setKeyPairAddress(adrs.getKeyPairAddress());
        return this.engine.T_l(pkSeed, forspkADRS, Arrays.concatenate(root));
    }

    static int[] message_to_idxs(byte[] msg, int fors_trees, int fors_height) {
        int offset = 0;
        int[] idxs = new int[fors_trees];
        for (int i = 0; i < fors_trees; i++) {
            idxs[i] = 0;
            for (int j = 0; j < fors_height; j++) {
                idxs[i] = idxs[i] ^ (((msg[offset >> 3] >> (offset & 7)) & 1) << j);
                offset++;
            }
        }
        return idxs;
    }
}
