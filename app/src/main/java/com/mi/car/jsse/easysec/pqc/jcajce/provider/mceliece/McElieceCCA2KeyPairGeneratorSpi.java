package com.mi.car.jsse.easysec.pqc.jcajce.provider.mceliece;

import com.mi.car.jsse.easysec.crypto.AsymmetricCipherKeyPair;
import com.mi.car.jsse.easysec.crypto.CryptoServicesRegistrar;
import com.mi.car.jsse.easysec.pqc.crypto.mceliece.McElieceCCA2KeyGenerationParameters;
import com.mi.car.jsse.easysec.pqc.crypto.mceliece.McElieceCCA2KeyPairGenerator;
import com.mi.car.jsse.easysec.pqc.crypto.mceliece.McElieceCCA2Parameters;
import com.mi.car.jsse.easysec.pqc.crypto.mceliece.McElieceCCA2PrivateKeyParameters;
import com.mi.car.jsse.easysec.pqc.crypto.mceliece.McElieceCCA2PublicKeyParameters;
import com.mi.car.jsse.easysec.pqc.jcajce.spec.McElieceCCA2KeyGenParameterSpec;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;

public class McElieceCCA2KeyPairGeneratorSpi extends KeyPairGenerator {
    private McElieceCCA2KeyPairGenerator kpg;

    public McElieceCCA2KeyPairGeneratorSpi() {
        super("McEliece-CCA2");
    }

    @Override // java.security.KeyPairGenerator, java.security.KeyPairGeneratorSpi
    public void initialize(AlgorithmParameterSpec params, SecureRandom random) throws InvalidAlgorithmParameterException {
        this.kpg = new McElieceCCA2KeyPairGenerator();
        McElieceCCA2KeyGenParameterSpec ecc = (McElieceCCA2KeyGenParameterSpec) params;
        this.kpg.init(new McElieceCCA2KeyGenerationParameters(random, new McElieceCCA2Parameters(ecc.getM(), ecc.getT(), ecc.getDigest())));
    }

    @Override // java.security.KeyPairGenerator
    public void initialize(AlgorithmParameterSpec params) throws InvalidAlgorithmParameterException {
        this.kpg = new McElieceCCA2KeyPairGenerator();
        McElieceCCA2KeyGenParameterSpec ecc = (McElieceCCA2KeyGenParameterSpec) params;
        this.kpg.init(new McElieceCCA2KeyGenerationParameters(CryptoServicesRegistrar.getSecureRandom(), new McElieceCCA2Parameters(ecc.getM(), ecc.getT(), ecc.getDigest())));
    }

    @Override // java.security.KeyPairGenerator, java.security.KeyPairGeneratorSpi
    public void initialize(int keySize, SecureRandom random) {
        this.kpg = new McElieceCCA2KeyPairGenerator();
        this.kpg.init(new McElieceCCA2KeyGenerationParameters(random, new McElieceCCA2Parameters()));
    }

    public KeyPair generateKeyPair() {
        AsymmetricCipherKeyPair generateKeyPair = this.kpg.generateKeyPair();
        return new KeyPair(new BCMcElieceCCA2PublicKey((McElieceCCA2PublicKeyParameters) generateKeyPair.getPublic()), new BCMcElieceCCA2PrivateKey((McElieceCCA2PrivateKeyParameters) generateKeyPair.getPrivate()));
    }
}
