package com.mi.car.jsse.easysec.pqc.crypto.saber;

import com.mi.car.jsse.easysec.crypto.EncapsulatedSecretExtractor;

public class SABERKEMExtractor implements EncapsulatedSecretExtractor {
    private SABEREngine engine;
    private SABERKeyParameters key;

    public SABERKEMExtractor(SABERKeyParameters privParams) {
        this.key = privParams;
        initCipher(this.key.getParameters());
    }

    private void initCipher(SABERParameters param) {
        this.engine = param.getEngine();
    }

    @Override // com.mi.car.jsse.easysec.crypto.EncapsulatedSecretExtractor
    public byte[] extractSecret(byte[] encapsulation) {
        byte[] session_key = new byte[this.engine.getSessionKeySize()];
        this.engine.crypto_kem_dec(session_key, encapsulation, ((SABERPrivateKeyParameters) this.key).getPrivateKey());
        return session_key;
    }

    public int getInputSize() {
        return this.engine.getCipherTextSize();
    }
}
