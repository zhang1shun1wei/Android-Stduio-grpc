package com.mi.car.jsse.easysec.pqc.crypto.cmce;

import com.mi.car.jsse.easysec.crypto.EncapsulatedSecretGenerator;
import com.mi.car.jsse.easysec.crypto.SecretWithEncapsulation;
import com.mi.car.jsse.easysec.crypto.params.AsymmetricKeyParameter;
import com.mi.car.jsse.easysec.pqc.crypto.util.SecretWithEncapsulationImpl;
import java.security.SecureRandom;

public class CMCEKEMGenerator implements EncapsulatedSecretGenerator {
    private final SecureRandom sr;

    public CMCEKEMGenerator(SecureRandom random) {
        this.sr = random;
    }

    @Override // com.mi.car.jsse.easysec.crypto.EncapsulatedSecretGenerator
    public SecretWithEncapsulation generateEncapsulated(AsymmetricKeyParameter recipientKey) {
        return generateEncapsulated(recipientKey, ((CMCEPublicKeyParameters) recipientKey).getParameters().getEngine().getDefaultSessionKeySize());
    }

    public SecretWithEncapsulation generateEncapsulated(AsymmetricKeyParameter recipientKey, int sessionKeySizeInBits) {
        CMCEPublicKeyParameters key = (CMCEPublicKeyParameters) recipientKey;
        CMCEEngine engine = key.getParameters().getEngine();
        byte[] cipher_text = new byte[engine.getCipherTextSize()];
        byte[] sessionKey = new byte[(sessionKeySizeInBits / 8)];
        engine.kem_enc(cipher_text, sessionKey, key.getPublicKey(), this.sr);
        return new SecretWithEncapsulationImpl(sessionKey, cipher_text);
    }
}
