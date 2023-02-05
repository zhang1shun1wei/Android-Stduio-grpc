package com.mi.car.jsse.easysec.pqc.jcajce.provider.lms;

import com.mi.car.jsse.easysec.asn1.ASN1ObjectIdentifier;
import com.mi.car.jsse.easysec.crypto.AsymmetricCipherKeyPair;
import com.mi.car.jsse.easysec.crypto.AsymmetricCipherKeyPairGenerator;
import com.mi.car.jsse.easysec.crypto.CryptoServicesRegistrar;
import com.mi.car.jsse.easysec.crypto.KeyGenerationParameters;
import com.mi.car.jsse.easysec.pqc.crypto.lms.HSSKeyGenerationParameters;
import com.mi.car.jsse.easysec.pqc.crypto.lms.HSSKeyPairGenerator;
import com.mi.car.jsse.easysec.pqc.crypto.lms.HSSPrivateKeyParameters;
import com.mi.car.jsse.easysec.pqc.crypto.lms.HSSPublicKeyParameters;
import com.mi.car.jsse.easysec.pqc.crypto.lms.LMOtsParameters;
import com.mi.car.jsse.easysec.pqc.crypto.lms.LMSKeyGenerationParameters;
import com.mi.car.jsse.easysec.pqc.crypto.lms.LMSKeyPairGenerator;
import com.mi.car.jsse.easysec.pqc.crypto.lms.LMSParameters;
import com.mi.car.jsse.easysec.pqc.crypto.lms.LMSPrivateKeyParameters;
import com.mi.car.jsse.easysec.pqc.crypto.lms.LMSPublicKeyParameters;
import com.mi.car.jsse.easysec.pqc.crypto.lms.LMSigParameters;
import com.mi.car.jsse.easysec.pqc.jcajce.spec.LMSHSSKeyGenParameterSpec;
import com.mi.car.jsse.easysec.pqc.jcajce.spec.LMSHSSParameterSpec;
import com.mi.car.jsse.easysec.pqc.jcajce.spec.LMSKeyGenParameterSpec;
import com.mi.car.jsse.easysec.pqc.jcajce.spec.LMSParameterSpec;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;

public class LMSKeyPairGeneratorSpi extends KeyPairGenerator {
    private AsymmetricCipherKeyPairGenerator engine = new LMSKeyPairGenerator();
    private boolean initialised = false;
    private KeyGenerationParameters param;
    private SecureRandom random = CryptoServicesRegistrar.getSecureRandom();
    private ASN1ObjectIdentifier treeDigest;

    public LMSKeyPairGeneratorSpi() {
        super("LMS");
    }

    @Override // java.security.KeyPairGenerator, java.security.KeyPairGeneratorSpi
    public void initialize(int strength, SecureRandom random2) {
        throw new IllegalArgumentException("use AlgorithmParameterSpec");
    }

    @Override // java.security.KeyPairGenerator, java.security.KeyPairGeneratorSpi
    public void initialize(AlgorithmParameterSpec params, SecureRandom random2) throws InvalidAlgorithmParameterException {
        if (params instanceof LMSKeyGenParameterSpec) {
            LMSKeyGenParameterSpec lmsParams = (LMSKeyGenParameterSpec) params;
            this.param = new LMSKeyGenerationParameters(new LMSParameters(lmsParams.getSigParams(), lmsParams.getOtsParams()), random2);
            this.engine = new LMSKeyPairGenerator();
            this.engine.init(this.param);
        } else if (params instanceof LMSHSSKeyGenParameterSpec) {
            LMSKeyGenParameterSpec[] lmsParams2 = ((LMSHSSKeyGenParameterSpec) params).getLMSSpecs();
            LMSParameters[] hssParams = new LMSParameters[lmsParams2.length];
            for (int i = 0; i != lmsParams2.length; i++) {
                hssParams[i] = new LMSParameters(lmsParams2[i].getSigParams(), lmsParams2[i].getOtsParams());
            }
            this.param = new HSSKeyGenerationParameters(hssParams, random2);
            this.engine = new HSSKeyPairGenerator();
            this.engine.init(this.param);
        } else if (params instanceof LMSParameterSpec) {
            LMSParameterSpec lmsParams3 = (LMSParameterSpec) params;
            this.param = new LMSKeyGenerationParameters(new LMSParameters(lmsParams3.getSigParams(), lmsParams3.getOtsParams()), random2);
            this.engine = new LMSKeyPairGenerator();
            this.engine.init(this.param);
        } else if (params instanceof LMSHSSParameterSpec) {
            LMSParameterSpec[] lmsParams4 = ((LMSHSSParameterSpec) params).getLMSSpecs();
            LMSParameters[] hssParams2 = new LMSParameters[lmsParams4.length];
            for (int i2 = 0; i2 != lmsParams4.length; i2++) {
                hssParams2[i2] = new LMSParameters(lmsParams4[i2].getSigParams(), lmsParams4[i2].getOtsParams());
            }
            this.param = new HSSKeyGenerationParameters(hssParams2, random2);
            this.engine = new HSSKeyPairGenerator();
            this.engine.init(this.param);
        } else {
            throw new InvalidAlgorithmParameterException("parameter object not a LMSParameterSpec/LMSHSSParameterSpec");
        }
        this.initialised = true;
    }

    public KeyPair generateKeyPair() {
        if (!this.initialised) {
            this.param = new LMSKeyGenerationParameters(new LMSParameters(LMSigParameters.lms_sha256_n32_h10, LMOtsParameters.sha256_n32_w2), this.random);
            this.engine.init(this.param);
            this.initialised = true;
        }
        AsymmetricCipherKeyPair pair = this.engine.generateKeyPair();
        if (this.engine instanceof LMSKeyPairGenerator) {
            return new KeyPair(new BCLMSPublicKey((LMSPublicKeyParameters) pair.getPublic()), new BCLMSPrivateKey((LMSPrivateKeyParameters) pair.getPrivate()));
        }
        return new KeyPair(new BCLMSPublicKey((HSSPublicKeyParameters) pair.getPublic()), new BCLMSPrivateKey((HSSPrivateKeyParameters) pair.getPrivate()));
    }
}
