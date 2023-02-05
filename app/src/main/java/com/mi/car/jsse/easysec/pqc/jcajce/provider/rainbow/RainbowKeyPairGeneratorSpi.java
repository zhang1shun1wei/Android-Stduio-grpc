package com.mi.car.jsse.easysec.pqc.jcajce.provider.rainbow;

import com.mi.car.jsse.easysec.crypto.AsymmetricCipherKeyPair;
import com.mi.car.jsse.easysec.crypto.CryptoServicesRegistrar;
import com.mi.car.jsse.easysec.pqc.crypto.rainbow.RainbowKeyGenerationParameters;
import com.mi.car.jsse.easysec.pqc.crypto.rainbow.RainbowKeyPairGenerator;
import com.mi.car.jsse.easysec.pqc.crypto.rainbow.RainbowParameters;
import com.mi.car.jsse.easysec.pqc.crypto.rainbow.RainbowPrivateKeyParameters;
import com.mi.car.jsse.easysec.pqc.crypto.rainbow.RainbowPublicKeyParameters;
import com.mi.car.jsse.easysec.pqc.jcajce.spec.RainbowParameterSpec;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;

public class RainbowKeyPairGeneratorSpi extends KeyPairGenerator {
    RainbowKeyPairGenerator engine = new RainbowKeyPairGenerator();
    boolean initialised = false;
    RainbowKeyGenerationParameters param;
    SecureRandom random = CryptoServicesRegistrar.getSecureRandom();
    int strength = 1024;

    public RainbowKeyPairGeneratorSpi() {
        super("Rainbow");
    }

    @Override // java.security.KeyPairGenerator, java.security.KeyPairGeneratorSpi
    public void initialize(int strength2, SecureRandom random2) {
        this.strength = strength2;
        this.random = random2;
    }

    @Override // java.security.KeyPairGenerator, java.security.KeyPairGeneratorSpi
    public void initialize(AlgorithmParameterSpec params, SecureRandom random2) throws InvalidAlgorithmParameterException {
        if (!(params instanceof RainbowParameterSpec)) {
            throw new InvalidAlgorithmParameterException("parameter object not a RainbowParameterSpec");
        }
        this.param = new RainbowKeyGenerationParameters(random2, new RainbowParameters(((RainbowParameterSpec) params).getVi()));
        this.engine.init(this.param);
        this.initialised = true;
    }

    public KeyPair generateKeyPair() {
        if (!this.initialised) {
            this.param = new RainbowKeyGenerationParameters(this.random, new RainbowParameters(new RainbowParameterSpec().getVi()));
            this.engine.init(this.param);
            this.initialised = true;
        }
        AsymmetricCipherKeyPair pair = this.engine.generateKeyPair();
        return new KeyPair(new BCRainbowPublicKey((RainbowPublicKeyParameters) pair.getPublic()), new BCRainbowPrivateKey((RainbowPrivateKeyParameters) pair.getPrivate()));
    }
}
