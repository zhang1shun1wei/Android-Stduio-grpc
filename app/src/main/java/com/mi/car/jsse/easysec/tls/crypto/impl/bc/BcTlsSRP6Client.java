package com.mi.car.jsse.easysec.tls.crypto.impl.bc;

import com.mi.car.jsse.easysec.crypto.CryptoException;
import com.mi.car.jsse.easysec.crypto.agreement.srp.SRP6Client;
import com.mi.car.jsse.easysec.tls.TlsFatalAlert;
import com.mi.car.jsse.easysec.tls.crypto.TlsSRP6Client;
import java.math.BigInteger;

final class BcTlsSRP6Client implements TlsSRP6Client {
    private final SRP6Client srp6Client;

    BcTlsSRP6Client(SRP6Client srpClient) {
        this.srp6Client = srpClient;
    }

    @Override // com.mi.car.jsse.easysec.tls.crypto.TlsSRP6Client
    public BigInteger calculateSecret(BigInteger serverB) throws TlsFatalAlert {
        try {
            return this.srp6Client.calculateSecret(serverB);
        } catch (CryptoException e) {
            throw new TlsFatalAlert((short) 47, (Throwable) e);
        }
    }

    @Override // com.mi.car.jsse.easysec.tls.crypto.TlsSRP6Client
    public BigInteger generateClientCredentials(byte[] srpSalt, byte[] identity, byte[] password) {
        return this.srp6Client.generateClientCredentials(srpSalt, identity, password);
    }
}
