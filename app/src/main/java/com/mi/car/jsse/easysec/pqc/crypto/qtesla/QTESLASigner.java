package com.mi.car.jsse.easysec.pqc.crypto.qtesla;

import com.mi.car.jsse.easysec.crypto.CipherParameters;
import com.mi.car.jsse.easysec.crypto.CryptoServicesRegistrar;
import com.mi.car.jsse.easysec.crypto.params.ParametersWithRandom;
import com.mi.car.jsse.easysec.pqc.crypto.MessageSigner;
import java.security.SecureRandom;

public class QTESLASigner implements MessageSigner {
    private QTESLAPrivateKeyParameters privateKey;
    private QTESLAPublicKeyParameters publicKey;
    private SecureRandom secureRandom;

    @Override // com.mi.car.jsse.easysec.pqc.crypto.MessageSigner
    public void init(boolean forSigning, CipherParameters param) {
        if (forSigning) {
            if (param instanceof ParametersWithRandom) {
                this.secureRandom = ((ParametersWithRandom) param).getRandom();
                this.privateKey = (QTESLAPrivateKeyParameters) ((ParametersWithRandom) param).getParameters();
            } else {
                this.secureRandom = CryptoServicesRegistrar.getSecureRandom();
                this.privateKey = (QTESLAPrivateKeyParameters) param;
            }
            this.publicKey = null;
            QTESLASecurityCategory.validate(this.privateKey.getSecurityCategory());
            return;
        }
        this.privateKey = null;
        this.publicKey = (QTESLAPublicKeyParameters) param;
        QTESLASecurityCategory.validate(this.publicKey.getSecurityCategory());
    }

    @Override // com.mi.car.jsse.easysec.pqc.crypto.MessageSigner
    public byte[] generateSignature(byte[] message) {
        byte[] sig = new byte[QTESLASecurityCategory.getSignatureSize(this.privateKey.getSecurityCategory())];
        switch (this.privateKey.getSecurityCategory()) {
            case 5:
                QTesla1p.generateSignature(sig, message, 0, message.length, this.privateKey.getSecret(), this.secureRandom);
                break;
            case 6:
                QTesla3p.generateSignature(sig, message, 0, message.length, this.privateKey.getSecret(), this.secureRandom);
                break;
            default:
                throw new IllegalArgumentException("unknown security category: " + this.privateKey.getSecurityCategory());
        }
        return sig;
    }

    @Override // com.mi.car.jsse.easysec.pqc.crypto.MessageSigner
    public boolean verifySignature(byte[] message, byte[] signature) {
        int status;
        switch (this.publicKey.getSecurityCategory()) {
            case 5:
                status = QTesla1p.verifying(message, signature, 0, signature.length, this.publicKey.getPublicData());
                break;
            case 6:
                status = QTesla3p.verifying(message, signature, 0, signature.length, this.publicKey.getPublicData());
                break;
            default:
                throw new IllegalArgumentException("unknown security category: " + this.publicKey.getSecurityCategory());
        }
        if (status == 0) {
            return true;
        }
        return false;
    }
}
