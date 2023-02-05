package com.mi.car.jsse.easysec.pqc.jcajce.provider.newhope;

import com.mi.car.jsse.easysec.crypto.AsymmetricCipherKeyPair;
import com.mi.car.jsse.easysec.crypto.CryptoServicesRegistrar;
import com.mi.car.jsse.easysec.crypto.KeyGenerationParameters;
import com.mi.car.jsse.easysec.pqc.crypto.newhope.NHKeyPairGenerator;
import com.mi.car.jsse.easysec.pqc.crypto.newhope.NHPrivateKeyParameters;
import com.mi.car.jsse.easysec.pqc.crypto.newhope.NHPublicKeyParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;

public class NHKeyPairGeneratorSpi extends KeyPairGenerator {
    NHKeyPairGenerator engine = new NHKeyPairGenerator();
    boolean initialised = false;
    SecureRandom random = CryptoServicesRegistrar.getSecureRandom();

    public NHKeyPairGeneratorSpi() {
        super("NH");
    }

    @Override // java.security.KeyPairGenerator, java.security.KeyPairGeneratorSpi
    public void initialize(int strength, SecureRandom random2) {
        if (strength != 1024) {
            throw new IllegalArgumentException("strength must be 1024 bits");
        }
        this.engine.init(new KeyGenerationParameters(random2, 1024));
        this.initialised = true;
    }

    @Override // java.security.KeyPairGenerator, java.security.KeyPairGeneratorSpi
    public void initialize(AlgorithmParameterSpec params, SecureRandom random2) throws InvalidAlgorithmParameterException {
        throw new InvalidAlgorithmParameterException("parameter object not recognised");
    }

    public KeyPair generateKeyPair() {
        if (!this.initialised) {
            this.engine.init(new KeyGenerationParameters(this.random, 1024));
            this.initialised = true;
        }
        AsymmetricCipherKeyPair pair = this.engine.generateKeyPair();
        return new KeyPair(new BCNHPublicKey((NHPublicKeyParameters) pair.getPublic()), new BCNHPrivateKey((NHPrivateKeyParameters) pair.getPrivate()));
    }
}
