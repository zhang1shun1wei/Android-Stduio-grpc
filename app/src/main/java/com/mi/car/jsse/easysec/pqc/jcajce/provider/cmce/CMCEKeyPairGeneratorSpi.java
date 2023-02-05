package com.mi.car.jsse.easysec.pqc.jcajce.provider.cmce;

import com.mi.car.jsse.easysec.crypto.AsymmetricCipherKeyPair;
import com.mi.car.jsse.easysec.crypto.CryptoServicesRegistrar;
import com.mi.car.jsse.easysec.pqc.crypto.cmce.CMCEKeyGenerationParameters;
import com.mi.car.jsse.easysec.pqc.crypto.cmce.CMCEKeyPairGenerator;
import com.mi.car.jsse.easysec.pqc.crypto.cmce.CMCEParameters;
import com.mi.car.jsse.easysec.pqc.crypto.cmce.CMCEPrivateKeyParameters;
import com.mi.car.jsse.easysec.pqc.crypto.cmce.CMCEPublicKeyParameters;
import com.mi.car.jsse.easysec.pqc.jcajce.provider.util.SpecUtil;
import com.mi.car.jsse.easysec.pqc.jcajce.spec.CMCEParameterSpec;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.util.HashMap;
import java.util.Map;

public class CMCEKeyPairGeneratorSpi extends KeyPairGenerator {
    private static Map parameters = new HashMap();
    CMCEKeyPairGenerator engine = new CMCEKeyPairGenerator();
    boolean initialised = false;
    CMCEKeyGenerationParameters param;
    SecureRandom random = CryptoServicesRegistrar.getSecureRandom();

    static {
        parameters.put(CMCEParameterSpec.mceliece348864.getName(), CMCEParameters.mceliece348864r3);
        parameters.put(CMCEParameterSpec.mceliece348864f.getName(), CMCEParameters.mceliece348864fr3);
        parameters.put(CMCEParameterSpec.mceliece460896.getName(), CMCEParameters.mceliece460896r3);
        parameters.put(CMCEParameterSpec.mceliece460896f.getName(), CMCEParameters.mceliece460896fr3);
        parameters.put(CMCEParameterSpec.mceliece6688128.getName(), CMCEParameters.mceliece6688128r3);
        parameters.put(CMCEParameterSpec.mceliece6688128f.getName(), CMCEParameters.mceliece6688128fr3);
        parameters.put(CMCEParameterSpec.mceliece6960119.getName(), CMCEParameters.mceliece6960119r3);
        parameters.put(CMCEParameterSpec.mceliece6960119f.getName(), CMCEParameters.mceliece6960119fr3);
        parameters.put(CMCEParameterSpec.mceliece8192128.getName(), CMCEParameters.mceliece8192128r3);
        parameters.put(CMCEParameterSpec.mceliece8192128f.getName(), CMCEParameters.mceliece8192128fr3);
    }

    public CMCEKeyPairGeneratorSpi() {
        super("CMCE");
    }

    @Override // java.security.KeyPairGenerator, java.security.KeyPairGeneratorSpi
    public void initialize(int strength, SecureRandom random2) {
        throw new IllegalArgumentException("use AlgorithmParameterSpec");
    }

    @Override // java.security.KeyPairGenerator, java.security.KeyPairGeneratorSpi
    public void initialize(AlgorithmParameterSpec params, SecureRandom random2) throws InvalidAlgorithmParameterException {
        if (!(params instanceof CMCEParameterSpec)) {
            throw new InvalidAlgorithmParameterException("parameter object not a CMCEParameterSpec");
        }
        this.param = new CMCEKeyGenerationParameters(random2, (CMCEParameters) parameters.get(getNameFromParams(params)));
        this.engine.init(this.param);
        this.initialised = true;
    }

    private static String getNameFromParams(AlgorithmParameterSpec paramSpec) throws InvalidAlgorithmParameterException {
        if (paramSpec instanceof CMCEParameterSpec) {
            return ((CMCEParameterSpec) paramSpec).getName();
        }
        return SpecUtil.getNameFrom(paramSpec);
    }

    public KeyPair generateKeyPair() {
        if (!this.initialised) {
            this.param = new CMCEKeyGenerationParameters(this.random, CMCEParameters.mceliece8192128fr3);
            this.engine.init(this.param);
            this.initialised = true;
        }
        AsymmetricCipherKeyPair pair = this.engine.generateKeyPair();
        return new KeyPair(new BCCMCEPublicKey((CMCEPublicKeyParameters) pair.getPublic()), new BCCMCEPrivateKey((CMCEPrivateKeyParameters) pair.getPrivate()));
    }
}
