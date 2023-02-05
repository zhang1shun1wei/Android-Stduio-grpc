package com.mi.car.jsse.easysec.pqc.crypto.frodo;

import com.mi.car.jsse.easysec.crypto.EncapsulatedSecretExtractor;

public class FrodoKEMExtractor implements EncapsulatedSecretExtractor {
    private FrodoEngine engine;
    private FrodoKeyParameters key;

    public FrodoKEMExtractor(FrodoKeyParameters privParams) {
        this.key = privParams;
        initCipher(this.key.getParameters());
    }

    private void initCipher(FrodoParameters param) {
        this.engine = param.getEngine();
    }

    @Override // com.mi.car.jsse.easysec.crypto.EncapsulatedSecretExtractor
    public byte[] extractSecret(byte[] encapsulation) {
        byte[] session_key = new byte[this.engine.getSessionKeySize()];
        this.engine.kem_dec(session_key, encapsulation, ((FrodoPrivateKeyParameters) this.key).getPrivateKey());
        return session_key;
    }

    public int getInputSize() {
        return this.engine.getCipherTextSize();
    }
}
