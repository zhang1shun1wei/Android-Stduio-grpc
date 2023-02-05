package com.mi.car.jsse.easysec.tls.crypto.impl.bc;

import com.mi.car.jsse.easysec.crypto.InvalidCipherTextException;
import com.mi.car.jsse.easysec.crypto.encodings.PKCS1Encoding;
import com.mi.car.jsse.easysec.crypto.engines.RSABlindedEngine;
import com.mi.car.jsse.easysec.crypto.params.ParametersWithRandom;
import com.mi.car.jsse.easysec.crypto.params.RSAKeyParameters;
import com.mi.car.jsse.easysec.tls.TlsFatalAlert;
import com.mi.car.jsse.easysec.tls.crypto.TlsEncryptor;
import java.io.IOException;

final class BcTlsRSAEncryptor implements TlsEncryptor {
    private final BcTlsCrypto crypto;
    private final RSAKeyParameters pubKeyRSA;

    private static RSAKeyParameters checkPublicKey(RSAKeyParameters pubKeyRSA2) {
        if (pubKeyRSA2 != null && !pubKeyRSA2.isPrivate()) {
            return pubKeyRSA2;
        }
        throw new IllegalArgumentException("No public RSA key provided");
    }

    BcTlsRSAEncryptor(BcTlsCrypto crypto2, RSAKeyParameters pubKeyRSA2) {
        this.crypto = crypto2;
        this.pubKeyRSA = checkPublicKey(pubKeyRSA2);
    }

    @Override // com.mi.car.jsse.easysec.tls.crypto.TlsEncryptor
    public byte[] encrypt(byte[] input, int inOff, int length) throws IOException {
        try {
            PKCS1Encoding encoding = new PKCS1Encoding(new RSABlindedEngine());
            encoding.init(true, new ParametersWithRandom(this.pubKeyRSA, this.crypto.getSecureRandom()));
            return encoding.processBlock(input, inOff, length);
        } catch (InvalidCipherTextException e) {
            throw new TlsFatalAlert((short) 80, (Throwable) e);
        }
    }
}
