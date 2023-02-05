package com.mi.car.jsse.easysec.tls.crypto.impl.bc;

import com.mi.car.jsse.easysec.math.ec.rfc7748.X448;
import com.mi.car.jsse.easysec.tls.TlsFatalAlert;
import com.mi.car.jsse.easysec.tls.crypto.TlsAgreement;
import com.mi.car.jsse.easysec.tls.crypto.TlsSecret;
import com.mi.car.jsse.easysec.util.Arrays;
import java.io.IOException;

public class BcX448 implements TlsAgreement {
    protected final BcTlsCrypto crypto;
    protected final byte[] peerPublicKey = new byte[56];
    protected final byte[] privateKey = new byte[56];

    public BcX448(BcTlsCrypto crypto2) {
        this.crypto = crypto2;
    }

    @Override // com.mi.car.jsse.easysec.tls.crypto.TlsAgreement
    public byte[] generateEphemeral() throws IOException {
        this.crypto.getSecureRandom().nextBytes(this.privateKey);
        byte[] publicKey = new byte[56];
        X448.scalarMultBase(this.privateKey, 0, publicKey, 0);
        return publicKey;
    }

    @Override // com.mi.car.jsse.easysec.tls.crypto.TlsAgreement
    public void receivePeerValue(byte[] peerValue) throws IOException {
        if (peerValue == null || peerValue.length != 56) {
            throw new TlsFatalAlert((short) 47);
        }
        System.arraycopy(peerValue, 0, this.peerPublicKey, 0, 56);
    }

    @Override // com.mi.car.jsse.easysec.tls.crypto.TlsAgreement
    public TlsSecret calculateSecret() throws IOException {
        try {
            byte[] secret = new byte[56];
            if (!X448.calculateAgreement(this.privateKey, 0, this.peerPublicKey, 0, secret, 0)) {
                throw new TlsFatalAlert((short) 40);
            }
            return this.crypto.adoptLocalSecret(secret);
        } finally {
            Arrays.fill(this.privateKey, (byte) 0);
            Arrays.fill(this.peerPublicKey, (byte) 0);
        }
    }
}
