package com.mi.car.jsse.easysec.tls.crypto.impl.bc;

import com.mi.car.jsse.easysec.crypto.CryptoException;
import com.mi.car.jsse.easysec.crypto.agreement.srp.SRP6Server;
import com.mi.car.jsse.easysec.tls.TlsFatalAlert;
import com.mi.car.jsse.easysec.tls.crypto.TlsSRP6Server;
import java.io.IOException;
import java.math.BigInteger;

final class BcTlsSRP6Server implements TlsSRP6Server {
    private final SRP6Server srp6Server;

    BcTlsSRP6Server(SRP6Server srp6Server2) {
        this.srp6Server = srp6Server2;
    }

    @Override // com.mi.car.jsse.easysec.tls.crypto.TlsSRP6Server
    public BigInteger generateServerCredentials() {
        return this.srp6Server.generateServerCredentials();
    }

    @Override // com.mi.car.jsse.easysec.tls.crypto.TlsSRP6Server
    public BigInteger calculateSecret(BigInteger clientA) throws IOException {
        try {
            return this.srp6Server.calculateSecret(clientA);
        } catch (CryptoException e) {
            throw new TlsFatalAlert((short) 47, (Throwable) e);
        }
    }
}
