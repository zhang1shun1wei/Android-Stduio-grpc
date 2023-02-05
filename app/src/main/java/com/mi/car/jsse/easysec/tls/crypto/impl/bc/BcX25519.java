package com.mi.car.jsse.easysec.tls.crypto.impl.bc;

import com.mi.car.jsse.easysec.math.ec.rfc7748.X25519;
import com.mi.car.jsse.easysec.tls.TlsFatalAlert;
import com.mi.car.jsse.easysec.tls.crypto.TlsAgreement;
import com.mi.car.jsse.easysec.tls.crypto.TlsSecret;
import com.mi.car.jsse.easysec.util.Arrays;
import java.io.IOException;

public class BcX25519 implements TlsAgreement {
    protected final BcTlsCrypto crypto;
    protected final byte[] peerPublicKey = new byte[32];
    protected final byte[] privateKey = new byte[32];

    public BcX25519(BcTlsCrypto crypto2) {
        this.crypto = crypto2;
    }

    @Override // com.mi.car.jsse.easysec.tls.crypto.TlsAgreement
    public byte[] generateEphemeral() throws IOException {
        this.crypto.getSecureRandom().nextBytes(this.privateKey);
        byte[] publicKey = new byte[32];
        X25519.scalarMultBase(this.privateKey, 0, publicKey, 0);
        return publicKey;
    }

    @Override // com.mi.car.jsse.easysec.tls.crypto.TlsAgreement
    public void receivePeerValue(byte[] peerValue) throws IOException {
        if (peerValue == null || peerValue.length != 32) {
            throw new TlsFatalAlert((short) 47);
        }
        System.arraycopy(peerValue, 0, this.peerPublicKey, 0, 32);
    }

    @Override // com.mi.car.jsse.easysec.tls.crypto.TlsAgreement
    public TlsSecret calculateSecret() throws IOException {
        try {
            byte[] secret = new byte[32];
            if (!X25519.calculateAgreement(this.privateKey, 0, this.peerPublicKey, 0, secret, 0)) {
                throw new TlsFatalAlert((short) 40);
            }
            return this.crypto.adoptLocalSecret(secret);
        } finally {
            Arrays.fill(this.privateKey, (byte) 0);
            Arrays.fill(this.peerPublicKey, (byte) 0);
        }
    }
}
