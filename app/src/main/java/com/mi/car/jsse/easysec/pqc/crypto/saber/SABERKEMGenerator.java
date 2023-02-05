package com.mi.car.jsse.easysec.pqc.crypto.saber;

import com.mi.car.jsse.easysec.crypto.EncapsulatedSecretGenerator;
import com.mi.car.jsse.easysec.crypto.SecretWithEncapsulation;
import com.mi.car.jsse.easysec.crypto.params.AsymmetricKeyParameter;
import com.mi.car.jsse.easysec.pqc.crypto.util.SecretWithEncapsulationImpl;
import java.security.SecureRandom;

public class SABERKEMGenerator implements EncapsulatedSecretGenerator {
    private final SecureRandom sr;

    public SABERKEMGenerator(SecureRandom random) {
        this.sr = random;
    }

    @Override // com.mi.car.jsse.easysec.crypto.EncapsulatedSecretGenerator
    public SecretWithEncapsulation generateEncapsulated(AsymmetricKeyParameter recipientKey) {
        SABERPublicKeyParameters key = (SABERPublicKeyParameters) recipientKey;
        SABEREngine engine = key.getParameters().getEngine();
        byte[] cipher_text = new byte[engine.getCipherTextSize()];
        byte[] sessionKey = new byte[engine.getSessionKeySize()];
        engine.crypto_kem_enc(cipher_text, sessionKey, key.getPublicKey(), this.sr);
        return new SecretWithEncapsulationImpl(sessionKey, cipher_text);
    }
}
