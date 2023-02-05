package com.mi.car.jsse.easysec.tls;

import com.mi.car.jsse.easysec.tls.crypto.TlsDHConfig;
import com.mi.car.jsse.easysec.tls.crypto.TlsECConfig;
import java.io.IOException;

public abstract class AbstractTlsKeyExchangeFactory implements TlsKeyExchangeFactory {
    @Override // com.mi.car.jsse.easysec.tls.TlsKeyExchangeFactory
    public TlsKeyExchange createDHKeyExchange(int keyExchange) throws IOException {
        throw new TlsFatalAlert((short) 80);
    }

    @Override // com.mi.car.jsse.easysec.tls.TlsKeyExchangeFactory
    public TlsKeyExchange createDHanonKeyExchangeClient(int keyExchange, TlsDHGroupVerifier dhGroupVerifier) throws IOException {
        throw new TlsFatalAlert((short) 80);
    }

    @Override // com.mi.car.jsse.easysec.tls.TlsKeyExchangeFactory
    public TlsKeyExchange createDHanonKeyExchangeServer(int keyExchange, TlsDHConfig dhConfig) throws IOException {
        throw new TlsFatalAlert((short) 80);
    }

    @Override // com.mi.car.jsse.easysec.tls.TlsKeyExchangeFactory
    public TlsKeyExchange createDHEKeyExchangeClient(int keyExchange, TlsDHGroupVerifier dhGroupVerifier) throws IOException {
        throw new TlsFatalAlert((short) 80);
    }

    @Override // com.mi.car.jsse.easysec.tls.TlsKeyExchangeFactory
    public TlsKeyExchange createDHEKeyExchangeServer(int keyExchange, TlsDHConfig dhConfig) throws IOException {
        throw new TlsFatalAlert((short) 80);
    }

    @Override // com.mi.car.jsse.easysec.tls.TlsKeyExchangeFactory
    public TlsKeyExchange createECDHKeyExchange(int keyExchange) throws IOException {
        throw new TlsFatalAlert((short) 80);
    }

    @Override // com.mi.car.jsse.easysec.tls.TlsKeyExchangeFactory
    public TlsKeyExchange createECDHanonKeyExchangeClient(int keyExchange) throws IOException {
        throw new TlsFatalAlert((short) 80);
    }

    @Override // com.mi.car.jsse.easysec.tls.TlsKeyExchangeFactory
    public TlsKeyExchange createECDHanonKeyExchangeServer(int keyExchange, TlsECConfig ecConfig) throws IOException {
        throw new TlsFatalAlert((short) 80);
    }

    @Override // com.mi.car.jsse.easysec.tls.TlsKeyExchangeFactory
    public TlsKeyExchange createECDHEKeyExchangeClient(int keyExchange) throws IOException {
        throw new TlsFatalAlert((short) 80);
    }

    @Override // com.mi.car.jsse.easysec.tls.TlsKeyExchangeFactory
    public TlsKeyExchange createECDHEKeyExchangeServer(int keyExchange, TlsECConfig ecConfig) throws IOException {
        throw new TlsFatalAlert((short) 80);
    }

    @Override // com.mi.car.jsse.easysec.tls.TlsKeyExchangeFactory
    public TlsKeyExchange createPSKKeyExchangeClient(int keyExchange, TlsPSKIdentity pskIdentity, TlsDHGroupVerifier dhGroupVerifier) throws IOException {
        throw new TlsFatalAlert((short) 80);
    }

    @Override // com.mi.car.jsse.easysec.tls.TlsKeyExchangeFactory
    public TlsKeyExchange createPSKKeyExchangeServer(int keyExchange, TlsPSKIdentityManager pskIdentityManager, TlsDHConfig dhConfig, TlsECConfig ecConfig) throws IOException {
        throw new TlsFatalAlert((short) 80);
    }

    @Override // com.mi.car.jsse.easysec.tls.TlsKeyExchangeFactory
    public TlsKeyExchange createRSAKeyExchange(int keyExchange) throws IOException {
        throw new TlsFatalAlert((short) 80);
    }

    @Override // com.mi.car.jsse.easysec.tls.TlsKeyExchangeFactory
    public TlsKeyExchange createSRPKeyExchangeClient(int keyExchange, TlsSRPIdentity srpIdentity, TlsSRPConfigVerifier srpConfigVerifier) throws IOException {
        throw new TlsFatalAlert((short) 80);
    }

    @Override // com.mi.car.jsse.easysec.tls.TlsKeyExchangeFactory
    public TlsKeyExchange createSRPKeyExchangeServer(int keyExchange, TlsSRPLoginParameters loginParameters) throws IOException {
        throw new TlsFatalAlert((short) 80);
    }
}
