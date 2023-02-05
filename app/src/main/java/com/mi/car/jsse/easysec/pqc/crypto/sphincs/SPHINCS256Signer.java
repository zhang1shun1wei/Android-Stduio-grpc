package com.mi.car.jsse.easysec.pqc.crypto.sphincs;

import com.mi.car.jsse.easysec.crypto.CipherParameters;
import com.mi.car.jsse.easysec.crypto.Digest;
import com.mi.car.jsse.easysec.crypto.params.ParametersWithRandom;
import com.mi.car.jsse.easysec.pqc.crypto.MessageSigner;
import com.mi.car.jsse.easysec.pqc.crypto.sphincs.Tree;
import com.mi.car.jsse.easysec.util.Pack;

public class SPHINCS256Signer implements MessageSigner {
    private final HashFunctions hashFunctions;
    private byte[] keyData;

    public SPHINCS256Signer(Digest nDigest, Digest twoNDigest) {
        if (nDigest.getDigestSize() != 32) {
            throw new IllegalArgumentException("n-digest needs to produce 32 bytes of output");
        } else if (twoNDigest.getDigestSize() != 64) {
            throw new IllegalArgumentException("2n-digest needs to produce 64 bytes of output");
        } else {
            this.hashFunctions = new HashFunctions(nDigest, twoNDigest);
        }
    }

    @Override // com.mi.car.jsse.easysec.pqc.crypto.MessageSigner
    public void init(boolean forSigning, CipherParameters param) {
        if (!forSigning) {
            this.keyData = ((SPHINCSPublicKeyParameters) param).getKeyData();
        } else if (param instanceof ParametersWithRandom) {
            this.keyData = ((SPHINCSPrivateKeyParameters) ((ParametersWithRandom) param).getParameters()).getKeyData();
        } else {
            this.keyData = ((SPHINCSPrivateKeyParameters) param).getKeyData();
        }
    }

    @Override // com.mi.car.jsse.easysec.pqc.crypto.MessageSigner
    public byte[] generateSignature(byte[] message) {
        return crypto_sign(this.hashFunctions, message, this.keyData);
    }

    @Override // com.mi.car.jsse.easysec.pqc.crypto.MessageSigner
    public boolean verifySignature(byte[] message, byte[] signature) {
        return verify(this.hashFunctions, message, signature, this.keyData);
    }

    static void validate_authpath(HashFunctions hs, byte[] root, byte[] leaf, int leafidx, byte[] authpath, int auOff, byte[] masks, int height) {
        byte[] buffer = new byte[64];
        if ((leafidx & 1) != 0) {
            for (int j = 0; j < 32; j++) {
                buffer[j + 32] = leaf[j];
            }
            for (int j2 = 0; j2 < 32; j2++) {
                buffer[j2] = authpath[auOff + j2];
            }
        } else {
            for (int j3 = 0; j3 < 32; j3++) {
                buffer[j3] = leaf[j3];
            }
            for (int j4 = 0; j4 < 32; j4++) {
                buffer[j4 + 32] = authpath[auOff + j4];
            }
        }
        int authOff = auOff + 32;
        for (int i = 0; i < height - 1; i++) {
            leafidx >>>= 1;
            if ((leafidx & 1) != 0) {
                hs.hash_2n_n_mask(buffer, 32, buffer, 0, masks, (i + 7) * 2 * 32);
                for (int j5 = 0; j5 < 32; j5++) {
                    buffer[j5] = authpath[authOff + j5];
                }
            } else {
                hs.hash_2n_n_mask(buffer, 0, buffer, 0, masks, (i + 7) * 2 * 32);
                for (int j6 = 0; j6 < 32; j6++) {
                    buffer[j6 + 32] = authpath[authOff + j6];
                }
            }
            authOff += 32;
        }
        hs.hash_2n_n_mask(root, 0, buffer, 0, masks, ((height + 7) - 1) * 2 * 32);
    }

    static void compute_authpath_wots(HashFunctions hs, byte[] root, byte[] authpath, int authOff, Tree.leafaddr a, byte[] sk, byte[] masks, int height) {
        Tree.leafaddr ta = new Tree.leafaddr(a);
        byte[] tree = new byte[2048];
        byte[] seed = new byte[1024];
        byte[] pk = new byte[68608];
        ta.subleaf = 0;
        while (ta.subleaf < 32) {
            Seed.get_seed(hs, seed, (int) (ta.subleaf * 32), sk, ta);
            ta.subleaf++;
        }
        Wots w = new Wots();
        ta.subleaf = 0;
        while (ta.subleaf < 32) {
            w.wots_pkgen(hs, pk, (int) (ta.subleaf * 67 * 32), seed, (int) (ta.subleaf * 32), masks, 0);
            ta.subleaf++;
        }
        ta.subleaf = 0;
        while (ta.subleaf < 32) {
            Tree.l_tree(hs, tree, (int) (1024 + (ta.subleaf * 32)), pk, (int) (ta.subleaf * 67 * 32), masks, 0);
            ta.subleaf++;
        }
        int level = 0;
        for (int i = 32; i > 0; i >>>= 1) {
            for (int j = 0; j < i; j += 2) {
                hs.hash_2n_n_mask(tree, ((i >>> 1) * 32) + ((j >>> 1) * 32), tree, (i * 32) + (j * 32), masks, (level + 7) * 2 * 32);
            }
            level++;
        }
        int idx = (int) a.subleaf;
        for (int i2 = 0; i2 < height; i2++) {
            System.arraycopy(tree, ((32 >>> i2) * 32) + (((idx >>> i2) ^ 1) * 32), authpath, (i2 * 32) + authOff, 32);
        }
        System.arraycopy(tree, 32, root, 0, 32);
    }

    /* access modifiers changed from: package-private */
    public byte[] crypto_sign(HashFunctions hs, byte[] m, byte[] sk) {
        byte[] sm = new byte[41000];
        byte[] R = new byte[32];
        byte[] m_h = new byte[64];
        long[] rnd = new long[8];
        byte[] root = new byte[32];
        byte[] seed = new byte[32];
        byte[] masks = new byte[1024];
        byte[] tsk = new byte[1088];
        for (int i = 0; i < 1088; i++) {
            tsk[i] = sk[i];
        }
        System.arraycopy(tsk, 1056, sm, 40968, 32);
        Digest d = hs.getMessageHash();
        byte[] bRnd = new byte[d.getDigestSize()];
        d.update(sm, 40968, 32);
        d.update(m, 0, m.length);
        d.doFinal(bRnd, 0);
        zerobytes(sm, 40968, 32);
        for (int j = 0; j != rnd.length; j++) {
            rnd[j] = Pack.littleEndianToLong(bRnd, j * 8);
        }
        long leafidx = rnd[0] & 1152921504606846975L;
        System.arraycopy(bRnd, 16, R, 0, 32);
        System.arraycopy(R, 0, sm, 39912, 32);
        Tree.leafaddr b = new Tree.leafaddr();
        b.level = 11;
        b.subtree = 0;
        b.subleaf = 0;
        int pk = 39912 + 32;
        System.arraycopy(tsk, 32, sm, pk, 1024);
        Tree.treehash(hs, sm, 40968, 5, tsk, b, sm, pk);
        Digest d2 = hs.getMessageHash();
        d2.update(sm, 39912, 1088);
        d2.update(m, 0, m.length);
        d2.doFinal(m_h, 0);
        Tree.leafaddr a = new Tree.leafaddr();
        a.level = 12;
        a.subleaf = (long) ((int) (31 & leafidx));
        a.subtree = leafidx >>> 5;
        for (int i2 = 0; i2 < 32; i2++) {
            sm[i2] = R[i2];
        }
        System.arraycopy(tsk, 32, masks, 0, 1024);
        for (int i3 = 0; i3 < 8; i3++) {
            sm[32 + i3] = (byte) ((int) ((leafidx >>> (i3 * 8)) & 255));
        }
        Seed.get_seed(hs, seed, 0, tsk, a);
        new Horst();
        int smOff = Horst.horst_sign(hs, sm, 32 + 8, root, seed, masks, m_h) + 40;
        Wots w = new Wots();
        for (int i4 = 0; i4 < 12; i4++) {
            a.level = i4;
            Seed.get_seed(hs, seed, 0, tsk, a);
            w.wots_sign(hs, sm, smOff, root, seed, masks);
            int smOff2 = smOff + 2144;
            compute_authpath_wots(hs, root, sm, smOff2, a, tsk, masks, 5);
            smOff = smOff2 + 160;
            a.subleaf = (long) ((int) (a.subtree & 31));
            a.subtree >>>= 5;
        }
        zerobytes(tsk, 0, 1088);
        return sm;
    }

    private void zerobytes(byte[] tsk, int off, int cryptoSecretkeybytes) {
        for (int i = 0; i != cryptoSecretkeybytes; i++) {
            tsk[off + i] = 0;
        }
    }

    /* access modifiers changed from: package-private */
    public boolean verify(HashFunctions hs, byte[] m, byte[] sm, byte[] pk) {
        int smlen = sm.length;
        long leafidx = 0;
        byte[] wots_pk = new byte[2144];
        byte[] pkhash = new byte[32];
        byte[] root = new byte[32];
        byte[] sig = new byte[41000];
        byte[] tpk = new byte[1056];
        if (smlen != 41000) {
            throw new IllegalArgumentException("signature wrong size");
        }
        byte[] m_h = new byte[64];
        for (int i = 0; i < 1056; i++) {
            tpk[i] = pk[i];
        }
        byte[] R = new byte[32];
        for (int i2 = 0; i2 < 32; i2++) {
            R[i2] = sm[i2];
        }
        System.arraycopy(sm, 0, sig, 0, 41000);
        Digest mHash = hs.getMessageHash();
        mHash.update(R, 0, 32);
        mHash.update(tpk, 0, 1056);
        mHash.update(m, 0, m.length);
        mHash.doFinal(m_h, 0);
        int sigp = 0 + 32;
        int smlen2 = smlen - 32;
        for (int i3 = 0; i3 < 8; i3++) {
            leafidx ^= ((long) (sig[i3 + 32] & 255)) << (i3 * 8);
        }
        new Horst();
        Horst.horst_verify(hs, root, sig, 40, tpk, m_h);
        int sigp2 = sigp + 8 + 13312;
        int smlen3 = (smlen2 - 8) - 13312;
        Wots w = new Wots();
        for (int i4 = 0; i4 < 12; i4++) {
            w.wots_verify(hs, wots_pk, sig, sigp2, root, tpk);
            int sigp3 = sigp2 + 2144;
            Tree.l_tree(hs, pkhash, 0, wots_pk, 0, tpk, 0);
            validate_authpath(hs, root, pkhash, (int) (31 & leafidx), sig, sigp3, tpk, 5);
            leafidx >>= 5;
            sigp2 = sigp3 + 160;
            smlen3 = (smlen3 - 2144) - 160;
        }
        boolean verified = true;
        for (int i5 = 0; i5 < 32; i5++) {
            if (root[i5] != tpk[i5 + 1024]) {
                verified = false;
            }
        }
        return verified;
    }
}
