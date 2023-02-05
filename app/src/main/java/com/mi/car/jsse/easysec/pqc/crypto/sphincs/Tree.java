package com.mi.car.jsse.easysec.pqc.crypto.sphincs;

class Tree {
    Tree() {
    }

    /* access modifiers changed from: package-private */
    public static class leafaddr {
        int level;
        long subleaf;
        long subtree;

        public leafaddr() {
        }

        public leafaddr(leafaddr leafaddr) {
            this.level = leafaddr.level;
            this.subtree = leafaddr.subtree;
            this.subleaf = leafaddr.subleaf;
        }
    }

    static void l_tree(HashFunctions hs, byte[] leaf, int leafOff, byte[] wots_pk, int pkOff, byte[] masks, int masksOff) {
        int l = 67;
        for (int i = 0; i < 7; i++) {
            for (int j = 0; j < (l >>> 1); j++) {
                hs.hash_2n_n_mask(wots_pk, pkOff + (j * 32), wots_pk, pkOff + (j * 2 * 32), masks, masksOff + (i * 2 * 32));
            }
            if ((l & 1) != 0) {
                System.arraycopy(wots_pk, ((l - 1) * 32) + pkOff, wots_pk, ((l >>> 1) * 32) + pkOff, 32);
                l = (l >>> 1) + 1;
            } else {
                l >>>= 1;
            }
        }
        System.arraycopy(wots_pk, pkOff, leaf, leafOff, 32);
    }

    static void treehash(HashFunctions hs, byte[] node, int nodeOff, int height, byte[] sk, leafaddr leaf, byte[] masks, int masksOff) {
        leafaddr a = new leafaddr(leaf);
        byte[] stack = new byte[((height + 1) * 32)];
        int[] stacklevels = new int[(height + 1)];
        int stackoffset = 0;
        int lastnode = (int) (a.subleaf + ((long) (1 << height)));
        while (a.subleaf < ((long) lastnode)) {
            gen_leaf_wots(hs, stack, stackoffset * 32, masks, masksOff, sk, a);
            stacklevels[stackoffset] = 0;
            stackoffset++;
            while (stackoffset > 1 && stacklevels[stackoffset - 1] == stacklevels[stackoffset - 2]) {
                hs.hash_2n_n_mask(stack, (stackoffset - 2) * 32, stack, (stackoffset - 2) * 32, masks, masksOff + ((stacklevels[stackoffset - 1] + 7) * 2 * 32));
                int i = stackoffset - 2;
                stacklevels[i] = stacklevels[i] + 1;
                stackoffset--;
            }
            a.subleaf++;
        }
        for (int i2 = 0; i2 < 32; i2++) {
            node[nodeOff + i2] = stack[i2];
        }
    }

    static void gen_leaf_wots(HashFunctions hs, byte[] leaf, int leafOff, byte[] masks, int masksOff, byte[] sk, leafaddr a) {
        byte[] seed = new byte[32];
        byte[] pk = new byte[2144];
        Wots w = new Wots();
        Seed.get_seed(hs, seed, 0, sk, a);
        w.wots_pkgen(hs, pk, 0, seed, 0, masks, masksOff);
        l_tree(hs, leaf, leafOff, pk, 0, masks, masksOff);
    }
}
