package com.mi.car.jsse.easysec.pqc.jcajce.provider.frodo;

import com.mi.car.jsse.easysec.crypto.AsymmetricCipherKeyPair;
import com.mi.car.jsse.easysec.crypto.CryptoServicesRegistrar;
import com.mi.car.jsse.easysec.pqc.crypto.frodo.FrodoKeyGenerationParameters;
import com.mi.car.jsse.easysec.pqc.crypto.frodo.FrodoKeyPairGenerator;
import com.mi.car.jsse.easysec.pqc.crypto.frodo.FrodoParameters;
import com.mi.car.jsse.easysec.pqc.crypto.frodo.FrodoPrivateKeyParameters;
import com.mi.car.jsse.easysec.pqc.crypto.frodo.FrodoPublicKeyParameters;
import com.mi.car.jsse.easysec.pqc.jcajce.provider.util.SpecUtil;
import com.mi.car.jsse.easysec.pqc.jcajce.spec.FrodoParameterSpec;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.util.HashMap;
import java.util.Map;

public class FrodoKeyPairGeneratorSpi extends KeyPairGenerator {
    private static Map parameters = new HashMap();
    FrodoKeyPairGenerator engine = new FrodoKeyPairGenerator();
    boolean initialised = false;
    FrodoKeyGenerationParameters param;
    SecureRandom random = CryptoServicesRegistrar.getSecureRandom();

    static {
        parameters.put(FrodoParameterSpec.frodokem19888r3.getName(), FrodoParameters.frodokem19888r3);
        parameters.put(FrodoParameterSpec.frodokem19888shaker3.getName(), FrodoParameters.frodokem19888shaker3);
        parameters.put(FrodoParameterSpec.frodokem31296r3.getName(), FrodoParameters.frodokem31296r3);
        parameters.put(FrodoParameterSpec.frodokem31296shaker3.getName(), FrodoParameters.frodokem31296shaker3);
        parameters.put(FrodoParameterSpec.frodokem43088r3.getName(), FrodoParameters.frodokem43088r3);
        parameters.put(FrodoParameterSpec.frodokem43088shaker3.getName(), FrodoParameters.frodokem43088shaker3);
    }

    public FrodoKeyPairGeneratorSpi() {
        super("Frodo");
    }

    @Override // java.security.KeyPairGenerator, java.security.KeyPairGeneratorSpi
    public void initialize(int strength, SecureRandom random2) {
        throw new IllegalArgumentException("use AlgorithmParameterSpec");
    }

    @Override // java.security.KeyPairGenerator, java.security.KeyPairGeneratorSpi
    public void initialize(AlgorithmParameterSpec params, SecureRandom random2) throws InvalidAlgorithmParameterException {
        if (!(params instanceof FrodoParameterSpec)) {
            throw new InvalidAlgorithmParameterException("parameter object not a FrodoParameterSpec");
        }
        this.param = new FrodoKeyGenerationParameters(random2, (FrodoParameters) parameters.get(getNameFromParams(params)));
        this.engine.init(this.param);
        this.initialised = true;
    }

    private static String getNameFromParams(AlgorithmParameterSpec paramSpec) throws InvalidAlgorithmParameterException {
        if (paramSpec instanceof FrodoParameterSpec) {
            return ((FrodoParameterSpec) paramSpec).getName();
        }
        return SpecUtil.getNameFrom(paramSpec);
    }

    public KeyPair generateKeyPair() {
        if (!this.initialised) {
            this.param = new FrodoKeyGenerationParameters(this.random, FrodoParameters.frodokem43088shaker3);
            this.engine.init(this.param);
            this.initialised = true;
        }
        AsymmetricCipherKeyPair pair = this.engine.generateKeyPair();
        return new KeyPair(new BCFrodoPublicKey((FrodoPublicKeyParameters) pair.getPublic()), new BCFrodoPrivateKey((FrodoPrivateKeyParameters) pair.getPrivate()));
    }
}
