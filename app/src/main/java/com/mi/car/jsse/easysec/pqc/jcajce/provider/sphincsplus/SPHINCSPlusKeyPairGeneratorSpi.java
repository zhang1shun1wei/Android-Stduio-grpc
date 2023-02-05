package com.mi.car.jsse.easysec.pqc.jcajce.provider.sphincsplus;

import com.mi.car.jsse.easysec.crypto.AsymmetricCipherKeyPair;
import com.mi.car.jsse.easysec.crypto.CryptoServicesRegistrar;
import com.mi.car.jsse.easysec.pqc.crypto.sphincsplus.SPHINCSPlusKeyGenerationParameters;
import com.mi.car.jsse.easysec.pqc.crypto.sphincsplus.SPHINCSPlusKeyPairGenerator;
import com.mi.car.jsse.easysec.pqc.crypto.sphincsplus.SPHINCSPlusParameters;
import com.mi.car.jsse.easysec.pqc.crypto.sphincsplus.SPHINCSPlusPrivateKeyParameters;
import com.mi.car.jsse.easysec.pqc.crypto.sphincsplus.SPHINCSPlusPublicKeyParameters;
import com.mi.car.jsse.easysec.pqc.jcajce.provider.util.SpecUtil;
import com.mi.car.jsse.easysec.pqc.jcajce.spec.SPHINCSPlusParameterSpec;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.util.HashMap;
import java.util.Map;

public class SPHINCSPlusKeyPairGeneratorSpi extends KeyPairGenerator {
    private static Map parameters = new HashMap();
    SPHINCSPlusKeyPairGenerator engine = new SPHINCSPlusKeyPairGenerator();
    boolean initialised = false;
    SPHINCSPlusKeyGenerationParameters param;
    SecureRandom random = CryptoServicesRegistrar.getSecureRandom();

    static {
        parameters.put(SPHINCSPlusParameterSpec.sha256_128f.getName(), SPHINCSPlusParameters.sha256_128f);
        parameters.put(SPHINCSPlusParameterSpec.sha256_128s.getName(), SPHINCSPlusParameters.sha256_128s);
        parameters.put(SPHINCSPlusParameterSpec.sha256_192f.getName(), SPHINCSPlusParameters.sha256_192f);
        parameters.put(SPHINCSPlusParameterSpec.sha256_192s.getName(), SPHINCSPlusParameters.sha256_192s);
        parameters.put(SPHINCSPlusParameterSpec.sha256_256f.getName(), SPHINCSPlusParameters.sha256_256f);
        parameters.put(SPHINCSPlusParameterSpec.sha256_256s.getName(), SPHINCSPlusParameters.sha256_256s);
        parameters.put(SPHINCSPlusParameterSpec.sha256_128f_simple.getName(), SPHINCSPlusParameters.sha256_128f_simple);
        parameters.put(SPHINCSPlusParameterSpec.sha256_128s_simple.getName(), SPHINCSPlusParameters.sha256_128s_simple);
        parameters.put(SPHINCSPlusParameterSpec.sha256_192f_simple.getName(), SPHINCSPlusParameters.sha256_192f_simple);
        parameters.put(SPHINCSPlusParameterSpec.sha256_192s_simple.getName(), SPHINCSPlusParameters.sha256_192s_simple);
        parameters.put(SPHINCSPlusParameterSpec.sha256_256f_simple.getName(), SPHINCSPlusParameters.sha256_256f_simple);
        parameters.put(SPHINCSPlusParameterSpec.sha256_256s_simple.getName(), SPHINCSPlusParameters.sha256_256s_simple);
        parameters.put(SPHINCSPlusParameterSpec.shake256_128f.getName(), SPHINCSPlusParameters.shake256_128f);
        parameters.put(SPHINCSPlusParameterSpec.shake256_128s.getName(), SPHINCSPlusParameters.shake256_128s);
        parameters.put(SPHINCSPlusParameterSpec.shake256_192f.getName(), SPHINCSPlusParameters.shake256_192f);
        parameters.put(SPHINCSPlusParameterSpec.shake256_192s.getName(), SPHINCSPlusParameters.shake256_192s);
        parameters.put(SPHINCSPlusParameterSpec.shake256_256f.getName(), SPHINCSPlusParameters.shake256_256f);
        parameters.put(SPHINCSPlusParameterSpec.shake256_256s.getName(), SPHINCSPlusParameters.shake256_256s);
        parameters.put(SPHINCSPlusParameterSpec.shake256_128f_simple.getName(), SPHINCSPlusParameters.shake256_128f_simple);
        parameters.put(SPHINCSPlusParameterSpec.shake256_128s_simple.getName(), SPHINCSPlusParameters.shake256_128s_simple);
        parameters.put(SPHINCSPlusParameterSpec.shake256_192f_simple.getName(), SPHINCSPlusParameters.shake256_192f_simple);
        parameters.put(SPHINCSPlusParameterSpec.shake256_192s_simple.getName(), SPHINCSPlusParameters.shake256_192s_simple);
        parameters.put(SPHINCSPlusParameterSpec.shake256_256f_simple.getName(), SPHINCSPlusParameters.shake256_256f_simple);
        parameters.put(SPHINCSPlusParameterSpec.shake256_256s_simple.getName(), SPHINCSPlusParameters.shake256_256s_simple);
    }

    public SPHINCSPlusKeyPairGeneratorSpi() {
        super("SPHINCS+");
    }

    @Override // java.security.KeyPairGenerator, java.security.KeyPairGeneratorSpi
    public void initialize(int strength, SecureRandom random2) {
        throw new IllegalArgumentException("use AlgorithmParameterSpec");
    }

    @Override // java.security.KeyPairGenerator, java.security.KeyPairGeneratorSpi
    public void initialize(AlgorithmParameterSpec params, SecureRandom random2) throws InvalidAlgorithmParameterException {
        if (!(params instanceof SPHINCSPlusParameterSpec)) {
            throw new InvalidAlgorithmParameterException("parameter object not a CMCEParameterSpec");
        }
        this.param = new SPHINCSPlusKeyGenerationParameters(random2, (SPHINCSPlusParameters) parameters.get(getNameFromParams(params)));
        this.engine.init(this.param);
        this.initialised = true;
    }

    public KeyPair generateKeyPair() {
        if (!this.initialised) {
            this.param = new SPHINCSPlusKeyGenerationParameters(this.random, SPHINCSPlusParameters.sha256_256s);
            this.engine.init(this.param);
            this.initialised = true;
        }
        AsymmetricCipherKeyPair pair = this.engine.generateKeyPair();
        return new KeyPair(new BCSPHINCSPlusPublicKey((SPHINCSPlusPublicKeyParameters) pair.getPublic()), new BCSPHINCSPlusPrivateKey((SPHINCSPlusPrivateKeyParameters) pair.getPrivate()));
    }

    private static String getNameFromParams(AlgorithmParameterSpec paramSpec) throws InvalidAlgorithmParameterException {
        if (paramSpec instanceof SPHINCSPlusParameterSpec) {
            return ((SPHINCSPlusParameterSpec) paramSpec).getName();
        }
        return SpecUtil.getNameFrom(paramSpec);
    }
}
