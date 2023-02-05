package com.mi.car.jsse.easysec.pqc.crypto.sphincs;

import com.mi.car.jsse.easysec.crypto.Digest;
import com.mi.car.jsse.easysec.crypto.KeyGenerationParameters;
import java.security.SecureRandom;

public class SPHINCS256KeyGenerationParameters extends KeyGenerationParameters {
    private final Digest treeDigest;

    public SPHINCS256KeyGenerationParameters(SecureRandom random, Digest treeDigest2) {
        super(random, 8448);
        this.treeDigest = treeDigest2;
    }

    public Digest getTreeDigest() {
        return this.treeDigest;
    }
}
