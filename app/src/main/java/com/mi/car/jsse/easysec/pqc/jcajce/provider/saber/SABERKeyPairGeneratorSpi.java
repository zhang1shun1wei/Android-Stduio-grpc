package com.mi.car.jsse.easysec.pqc.jcajce.provider.saber;

import com.mi.car.jsse.easysec.crypto.AsymmetricCipherKeyPair;
import com.mi.car.jsse.easysec.crypto.CryptoServicesRegistrar;
import com.mi.car.jsse.easysec.pqc.crypto.saber.SABERKeyGenerationParameters;
import com.mi.car.jsse.easysec.pqc.crypto.saber.SABERKeyPairGenerator;
import com.mi.car.jsse.easysec.pqc.crypto.saber.SABERParameters;
import com.mi.car.jsse.easysec.pqc.crypto.saber.SABERPrivateKeyParameters;
import com.mi.car.jsse.easysec.pqc.crypto.saber.SABERPublicKeyParameters;
import com.mi.car.jsse.easysec.pqc.jcajce.provider.util.SpecUtil;
import com.mi.car.jsse.easysec.pqc.jcajce.spec.SABERParameterSpec;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.util.HashMap;
import java.util.Map;

public class SABERKeyPairGeneratorSpi extends KeyPairGenerator {
    private static Map parameters = new HashMap();
    SABERKeyPairGenerator engine = new SABERKeyPairGenerator();
    boolean initialised = false;
    SABERKeyGenerationParameters param;
    SecureRandom random = CryptoServicesRegistrar.getSecureRandom();

    static {
        parameters.put(SABERParameterSpec.lightsaberkem128r3.getName(), SABERParameters.lightsaberkem128r3);
        parameters.put(SABERParameterSpec.saberkem128r3.getName(), SABERParameters.saberkem128r3);
        parameters.put(SABERParameterSpec.firesaberkem128r3.getName(), SABERParameters.firesaberkem128r3);
        parameters.put(SABERParameterSpec.lightsaberkem192r3.getName(), SABERParameters.lightsaberkem192r3);
        parameters.put(SABERParameterSpec.saberkem192r3.getName(), SABERParameters.saberkem192r3);
        parameters.put(SABERParameterSpec.firesaberkem192r3.getName(), SABERParameters.firesaberkem192r3);
        parameters.put(SABERParameterSpec.lightsaberkem256r3.getName(), SABERParameters.lightsaberkem256r3);
        parameters.put(SABERParameterSpec.saberkem256r3.getName(), SABERParameters.saberkem256r3);
        parameters.put(SABERParameterSpec.firesaberkem256r3.getName(), SABERParameters.firesaberkem256r3);
    }

    public SABERKeyPairGeneratorSpi() {
        super("SABER");
    }

    @Override // java.security.KeyPairGenerator, java.security.KeyPairGeneratorSpi
    public void initialize(int strength, SecureRandom random2) {
        throw new IllegalArgumentException("use AlgorithmParameterSpec");
    }

    @Override // java.security.KeyPairGenerator, java.security.KeyPairGeneratorSpi
    public void initialize(AlgorithmParameterSpec params, SecureRandom random2) throws InvalidAlgorithmParameterException {
        if (!(params instanceof SABERParameterSpec)) {
            throw new InvalidAlgorithmParameterException("parameter object not a SABERParameterSpec");
        }
        this.param = new SABERKeyGenerationParameters(random2, (SABERParameters) parameters.get(getNameFromParams(params)));
        this.engine.init(this.param);
        this.initialised = true;
    }

    private static String getNameFromParams(AlgorithmParameterSpec paramSpec) throws InvalidAlgorithmParameterException {
        if (paramSpec instanceof SABERParameterSpec) {
            return ((SABERParameterSpec) paramSpec).getName();
        }
        return SpecUtil.getNameFrom(paramSpec);
    }

    public KeyPair generateKeyPair() {
        if (!this.initialised) {
            this.param = new SABERKeyGenerationParameters(this.random, SABERParameters.firesaberkem256r3);
            this.engine.init(this.param);
            this.initialised = true;
        }
        AsymmetricCipherKeyPair pair = this.engine.generateKeyPair();
        return new KeyPair(new BCSABERPublicKey((SABERPublicKeyParameters) pair.getPublic()), new BCSABERPrivateKey((SABERPrivateKeyParameters) pair.getPrivate()));
    }
}
