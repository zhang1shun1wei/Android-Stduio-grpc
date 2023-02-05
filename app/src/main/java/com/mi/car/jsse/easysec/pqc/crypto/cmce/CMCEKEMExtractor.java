package com.mi.car.jsse.easysec.pqc.crypto.cmce;

import com.mi.car.jsse.easysec.crypto.EncapsulatedSecretExtractor;

public class CMCEKEMExtractor implements EncapsulatedSecretExtractor {
    private CMCEEngine engine;
    private CMCEKeyParameters key;

    public CMCEKEMExtractor(CMCEPrivateKeyParameters privParams) {
        this.key = privParams;
        initCipher(this.key.getParameters());
    }

    private void initCipher(CMCEParameters param) {
        this.engine = param.getEngine();
        CMCEPrivateKeyParameters privateParams = (CMCEPrivateKeyParameters) this.key;
        if (privateParams.getPrivateKey().length < this.engine.getPrivateKeySize()) {
            this.key = new CMCEPrivateKeyParameters(privateParams.getParameters(), this.engine.decompress_private_key(privateParams.getPrivateKey()));
        }
    }

    @Override // com.mi.car.jsse.easysec.crypto.EncapsulatedSecretExtractor
    public byte[] extractSecret(byte[] encapsulation) {
        return extractSecret(encapsulation, this.engine.getDefaultSessionKeySize());
    }

    public byte[] extractSecret(byte[] encapsulation, int sessionKeySizeInBits) {
        byte[] session_key = new byte[(sessionKeySizeInBits / 8)];
        this.engine.kem_dec(session_key, encapsulation, ((CMCEPrivateKeyParameters) this.key).getPrivateKey());
        return session_key;
    }

    public int getInputSize() {
        return this.engine.getCipherTextSize();
    }
}
