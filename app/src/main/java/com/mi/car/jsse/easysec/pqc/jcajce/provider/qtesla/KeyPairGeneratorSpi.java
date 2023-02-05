package com.mi.car.jsse.easysec.pqc.jcajce.provider.qtesla;

import com.mi.car.jsse.easysec.crypto.AsymmetricCipherKeyPair;
import com.mi.car.jsse.easysec.crypto.CryptoServicesRegistrar;
import com.mi.car.jsse.easysec.pqc.crypto.qtesla.QTESLAKeyGenerationParameters;
import com.mi.car.jsse.easysec.pqc.crypto.qtesla.QTESLAKeyPairGenerator;
import com.mi.car.jsse.easysec.pqc.crypto.qtesla.QTESLAPrivateKeyParameters;
import com.mi.car.jsse.easysec.pqc.crypto.qtesla.QTESLAPublicKeyParameters;
import com.mi.car.jsse.easysec.pqc.crypto.qtesla.QTESLASecurityCategory;
import com.mi.car.jsse.easysec.pqc.jcajce.spec.QTESLAParameterSpec;
import com.mi.car.jsse.easysec.util.Integers;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.util.HashMap;
import java.util.Map;

public class KeyPairGeneratorSpi extends KeyPairGenerator {
    private static final Map catLookup = new HashMap();
    private QTESLAKeyPairGenerator engine = new QTESLAKeyPairGenerator();
    private boolean initialised = false;
    private QTESLAKeyGenerationParameters param;
    private SecureRandom random = CryptoServicesRegistrar.getSecureRandom();

    static {
        catLookup.put(QTESLASecurityCategory.getName(5), Integers.valueOf(5));
        catLookup.put(QTESLASecurityCategory.getName(6), Integers.valueOf(6));
    }

    public KeyPairGeneratorSpi() {
        super("qTESLA");
    }

    @Override // java.security.KeyPairGenerator, java.security.KeyPairGeneratorSpi
    public void initialize(int strength, SecureRandom random2) {
        throw new IllegalArgumentException("use AlgorithmParameterSpec");
    }

    @Override // java.security.KeyPairGenerator, java.security.KeyPairGeneratorSpi
    public void initialize(AlgorithmParameterSpec params, SecureRandom random2) throws InvalidAlgorithmParameterException {
        if (!(params instanceof QTESLAParameterSpec)) {
            throw new InvalidAlgorithmParameterException("parameter object not a QTESLAParameterSpec");
        }
        this.param = new QTESLAKeyGenerationParameters(((Integer) catLookup.get(((QTESLAParameterSpec) params).getSecurityCategory())).intValue(), random2);
        this.engine.init(this.param);
        this.initialised = true;
    }

    public KeyPair generateKeyPair() {
        if (!this.initialised) {
            this.param = new QTESLAKeyGenerationParameters(6, this.random);
            this.engine.init(this.param);
            this.initialised = true;
        }
        AsymmetricCipherKeyPair pair = this.engine.generateKeyPair();
        return new KeyPair(new BCqTESLAPublicKey((QTESLAPublicKeyParameters) pair.getPublic()), new BCqTESLAPrivateKey((QTESLAPrivateKeyParameters) pair.getPrivate()));
    }
}
