package com.mi.car.jsse.easysec.pqc.crypto.sphincsplus;

import com.mi.car.jsse.easysec.crypto.CipherParameters;
import com.mi.car.jsse.easysec.crypto.params.ParametersWithRandom;
import com.mi.car.jsse.easysec.pqc.crypto.MessageSigner;
import com.mi.car.jsse.easysec.util.Arrays;
import java.security.SecureRandom;

public class SPHINCSPlusSigner implements MessageSigner {
    private SPHINCSPlusPrivateKeyParameters privKey;
    private SPHINCSPlusPublicKeyParameters pubKey;
    private SecureRandom random;

    @Override // com.mi.car.jsse.easysec.pqc.crypto.MessageSigner
    public void init(boolean forSigning, CipherParameters param) {
        if (!forSigning) {
            this.pubKey = (SPHINCSPlusPublicKeyParameters) param;
        } else if (param instanceof ParametersWithRandom) {
            this.privKey = (SPHINCSPlusPrivateKeyParameters) ((ParametersWithRandom) param).getParameters();
            this.random = ((ParametersWithRandom) param).getRandom();
        } else {
            this.privKey = (SPHINCSPlusPrivateKeyParameters) param;
        }
    }

    @Override // com.mi.car.jsse.easysec.pqc.crypto.MessageSigner
    public byte[] generateSignature(byte[] message) {
        SPHINCSPlusEngine engine = this.privKey.getParameters().getEngine();
        byte[] optRand = new byte[engine.N];
        if (this.random != null) {
            this.random.nextBytes(optRand);
        } else {
            System.arraycopy(this.privKey.pk.seed, 0, optRand, 0, optRand.length);
        }
        Fors fors = new Fors(engine);
        byte[] R = engine.PRF_msg(this.privKey.sk.prf, optRand, message);
        IndexedDigest idxDigest = engine.H_msg(R, this.privKey.pk.seed, this.privKey.pk.root, message);
        byte[] mHash = idxDigest.digest;
        long idx_tree = idxDigest.idx_tree;
        int idx_leaf = idxDigest.idx_leaf;
        ADRS adrs = new ADRS();
        adrs.setType(3);
        adrs.setTreeAddress(idx_tree);
        adrs.setKeyPairAddress(idx_leaf);
        SIG_FORS[] sig_fors = fors.sign(mHash, this.privKey.sk.seed, this.privKey.pk.seed, adrs);
        byte[] PK_FORS = fors.pkFromSig(sig_fors, mHash, this.privKey.pk.seed, adrs);
        new ADRS().setType(2);
        byte[] SIG_HT = new HT(engine, this.privKey.getSeed(), this.privKey.getPublicSeed()).sign(PK_FORS, idx_tree, idx_leaf);
        byte[][] sigComponents = new byte[(sig_fors.length + 2)][];
        sigComponents[0] = R;
        for (int i = 0; i != sig_fors.length; i++) {
            sigComponents[i + 1] = Arrays.concatenate(sig_fors[i].sk, Arrays.concatenate(sig_fors[i].authPath));
        }
        sigComponents[sigComponents.length - 1] = SIG_HT;
        return Arrays.concatenate(sigComponents);
    }

    @Override // com.mi.car.jsse.easysec.pqc.crypto.MessageSigner
    public boolean verifySignature(byte[] message, byte[] signature) {
        SPHINCSPlusEngine engine = this.pubKey.getParameters().getEngine();
        ADRS adrs = new ADRS();
        SIG sig = new SIG(engine.N, engine.K, engine.A, engine.D, engine.H_PRIME, engine.WOTS_LEN, signature);
        byte[] R = sig.getR();
        SIG_FORS[] sig_fors = sig.getSIG_FORS();
        SIG_XMSS[] SIG_HT = sig.getSIG_HT();
        IndexedDigest idxDigest = engine.H_msg(R, this.pubKey.getSeed(), this.pubKey.getRoot(), message);
        byte[] mHash = idxDigest.digest;
        long idx_tree = idxDigest.idx_tree;
        int idx_leaf = idxDigest.idx_leaf;
        adrs.setLayerAddress(0);
        adrs.setTreeAddress(idx_tree);
        adrs.setType(3);
        adrs.setKeyPairAddress(idx_leaf);
        byte[] PK_FORS = new Fors(engine).pkFromSig(sig_fors, mHash, this.pubKey.getSeed(), adrs);
        adrs.setType(2);
        return new HT(engine, null, this.pubKey.getSeed()).verify(PK_FORS, SIG_HT, this.pubKey.getSeed(), idx_tree, idx_leaf, this.pubKey.getRoot());
    }
}
