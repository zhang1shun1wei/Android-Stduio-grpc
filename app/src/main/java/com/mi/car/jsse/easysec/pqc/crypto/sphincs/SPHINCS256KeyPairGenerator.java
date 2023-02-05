package com.mi.car.jsse.easysec.pqc.crypto.sphincs;

import com.mi.car.jsse.easysec.crypto.AsymmetricCipherKeyPair;
import com.mi.car.jsse.easysec.crypto.AsymmetricCipherKeyPairGenerator;
import com.mi.car.jsse.easysec.crypto.Digest;
import com.mi.car.jsse.easysec.crypto.KeyGenerationParameters;
import com.mi.car.jsse.easysec.crypto.params.AsymmetricKeyParameter;
import com.mi.car.jsse.easysec.pqc.crypto.sphincs.Tree;
import java.security.SecureRandom;

public class SPHINCS256KeyPairGenerator implements AsymmetricCipherKeyPairGenerator {
    private SecureRandom random;
    private Digest treeDigest;

    @Override // com.mi.car.jsse.easysec.crypto.AsymmetricCipherKeyPairGenerator
    public void init(KeyGenerationParameters param) {
        this.random = param.getRandom();
        this.treeDigest = ((SPHINCS256KeyGenerationParameters) param).getTreeDigest();
    }

    @Override // com.mi.car.jsse.easysec.crypto.AsymmetricCipherKeyPairGenerator
    public AsymmetricCipherKeyPair generateKeyPair() {
        Tree.leafaddr a = new Tree.leafaddr();
        byte[] sk = new byte[1088];
        this.random.nextBytes(sk);
        byte[] pk = new byte[1056];
        System.arraycopy(sk, 32, pk, 0, 1024);
        a.level = 11;
        a.subtree = 0;
        a.subleaf = 0;
        Tree.treehash(new HashFunctions(this.treeDigest), pk, 1024, 5, sk, a, pk, 0);
        return new AsymmetricCipherKeyPair((AsymmetricKeyParameter) new SPHINCSPublicKeyParameters(pk, this.treeDigest.getAlgorithmName()), (AsymmetricKeyParameter) new SPHINCSPrivateKeyParameters(sk, this.treeDigest.getAlgorithmName()));
    }
}
