package com.mi.car.jsse.easysec.pqc.crypto.sphincsplus;

class IndexedDigest {
    final byte[] digest;
    final int idx_leaf;
    final long idx_tree;

    IndexedDigest(long idx_tree2, int idx_leaf2, byte[] digest2) {
        this.idx_tree = idx_tree2;
        this.idx_leaf = idx_leaf2;
        this.digest = digest2;
    }
}
