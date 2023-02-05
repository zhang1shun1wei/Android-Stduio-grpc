package com.mi.car.jsse.easysec.pqc.jcajce.provider.mceliece;

import com.mi.car.jsse.easysec.crypto.AsymmetricCipherKeyPair;
import com.mi.car.jsse.easysec.pqc.crypto.mceliece.McElieceKeyGenerationParameters;
import com.mi.car.jsse.easysec.pqc.crypto.mceliece.McElieceKeyPairGenerator;
import com.mi.car.jsse.easysec.pqc.crypto.mceliece.McElieceParameters;
import com.mi.car.jsse.easysec.pqc.crypto.mceliece.McEliecePrivateKeyParameters;
import com.mi.car.jsse.easysec.pqc.crypto.mceliece.McEliecePublicKeyParameters;
import com.mi.car.jsse.easysec.pqc.jcajce.spec.McElieceKeyGenParameterSpec;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;

public class McElieceKeyPairGeneratorSpi extends KeyPairGenerator {
    McElieceKeyPairGenerator kpg;

    public McElieceKeyPairGeneratorSpi() {
        super("McEliece");
    }

    @Override // java.security.KeyPairGenerator, java.security.KeyPairGeneratorSpi
    public void initialize(AlgorithmParameterSpec params, SecureRandom random) throws InvalidAlgorithmParameterException {
        this.kpg = new McElieceKeyPairGenerator();
        McElieceKeyGenParameterSpec ecc = (McElieceKeyGenParameterSpec) params;
        this.kpg.init(new McElieceKeyGenerationParameters(random, new McElieceParameters(ecc.getM(), ecc.getT())));
    }

    @Override // java.security.KeyPairGenerator, java.security.KeyPairGeneratorSpi
    public void initialize(int keySize, SecureRandom random) {
        try {
            initialize(new McElieceKeyGenParameterSpec(), random);
        } catch (InvalidAlgorithmParameterException e) {
        }
    }

    public KeyPair generateKeyPair() {
        AsymmetricCipherKeyPair generateKeyPair = this.kpg.generateKeyPair();
        return new KeyPair(new BCMcEliecePublicKey((McEliecePublicKeyParameters) generateKeyPair.getPublic()), new BCMcEliecePrivateKey((McEliecePrivateKeyParameters) generateKeyPair.getPrivate()));
    }
}
