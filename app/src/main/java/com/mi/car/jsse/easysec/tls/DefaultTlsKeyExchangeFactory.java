package com.mi.car.jsse.easysec.tls;

import com.mi.car.jsse.easysec.tls.crypto.TlsDHConfig;
import com.mi.car.jsse.easysec.tls.crypto.TlsECConfig;
import java.io.IOException;

public class DefaultTlsKeyExchangeFactory extends AbstractTlsKeyExchangeFactory {
    @Override // com.mi.car.jsse.easysec.tls.TlsKeyExchangeFactory, com.mi.car.jsse.easysec.tls.AbstractTlsKeyExchangeFactory
    public TlsKeyExchange createDHKeyExchange(int keyExchange) throws IOException {
        return new TlsDHKeyExchange(keyExchange);
    }

    @Override // com.mi.car.jsse.easysec.tls.TlsKeyExchangeFactory, com.mi.car.jsse.easysec.tls.AbstractTlsKeyExchangeFactory
    public TlsKeyExchange createDHanonKeyExchangeClient(int keyExchange, TlsDHGroupVerifier dhGroupVerifier) throws IOException {
        return new TlsDHanonKeyExchange(keyExchange, dhGroupVerifier);
    }

    @Override // com.mi.car.jsse.easysec.tls.TlsKeyExchangeFactory, com.mi.car.jsse.easysec.tls.AbstractTlsKeyExchangeFactory
    public TlsKeyExchange createDHanonKeyExchangeServer(int keyExchange, TlsDHConfig dhConfig) throws IOException {
        return new TlsDHanonKeyExchange(keyExchange, dhConfig);
    }

    @Override // com.mi.car.jsse.easysec.tls.TlsKeyExchangeFactory, com.mi.car.jsse.easysec.tls.AbstractTlsKeyExchangeFactory
    public TlsKeyExchange createDHEKeyExchangeClient(int keyExchange, TlsDHGroupVerifier dhGroupVerifier) throws IOException {
        return new TlsDHEKeyExchange(keyExchange, dhGroupVerifier);
    }

    @Override // com.mi.car.jsse.easysec.tls.TlsKeyExchangeFactory, com.mi.car.jsse.easysec.tls.AbstractTlsKeyExchangeFactory
    public TlsKeyExchange createDHEKeyExchangeServer(int keyExchange, TlsDHConfig dhConfig) throws IOException {
        return new TlsDHEKeyExchange(keyExchange, dhConfig);
    }

    @Override // com.mi.car.jsse.easysec.tls.TlsKeyExchangeFactory, com.mi.car.jsse.easysec.tls.AbstractTlsKeyExchangeFactory
    public TlsKeyExchange createECDHKeyExchange(int keyExchange) throws IOException {
        return new TlsECDHKeyExchange(keyExchange);
    }

    @Override // com.mi.car.jsse.easysec.tls.TlsKeyExchangeFactory, com.mi.car.jsse.easysec.tls.AbstractTlsKeyExchangeFactory
    public TlsKeyExchange createECDHanonKeyExchangeClient(int keyExchange) throws IOException {
        return new TlsECDHanonKeyExchange(keyExchange);
    }

    @Override // com.mi.car.jsse.easysec.tls.TlsKeyExchangeFactory, com.mi.car.jsse.easysec.tls.AbstractTlsKeyExchangeFactory
    public TlsKeyExchange createECDHanonKeyExchangeServer(int keyExchange, TlsECConfig ecConfig) throws IOException {
        return new TlsECDHanonKeyExchange(keyExchange, ecConfig);
    }

    @Override // com.mi.car.jsse.easysec.tls.TlsKeyExchangeFactory, com.mi.car.jsse.easysec.tls.AbstractTlsKeyExchangeFactory
    public TlsKeyExchange createECDHEKeyExchangeClient(int keyExchange) throws IOException {
        return new TlsECDHEKeyExchange(keyExchange);
    }

    @Override // com.mi.car.jsse.easysec.tls.TlsKeyExchangeFactory, com.mi.car.jsse.easysec.tls.AbstractTlsKeyExchangeFactory
    public TlsKeyExchange createECDHEKeyExchangeServer(int keyExchange, TlsECConfig ecConfig) throws IOException {
        return new TlsECDHEKeyExchange(keyExchange, ecConfig);
    }

    @Override // com.mi.car.jsse.easysec.tls.TlsKeyExchangeFactory, com.mi.car.jsse.easysec.tls.AbstractTlsKeyExchangeFactory
    public TlsKeyExchange createPSKKeyExchangeClient(int keyExchange, TlsPSKIdentity pskIdentity, TlsDHGroupVerifier dhGroupVerifier) throws IOException {
        return new TlsPSKKeyExchange(keyExchange, pskIdentity, dhGroupVerifier);
    }

    @Override // com.mi.car.jsse.easysec.tls.TlsKeyExchangeFactory, com.mi.car.jsse.easysec.tls.AbstractTlsKeyExchangeFactory
    public TlsKeyExchange createPSKKeyExchangeServer(int keyExchange, TlsPSKIdentityManager pskIdentityManager, TlsDHConfig dhConfig, TlsECConfig ecConfig) throws IOException {
        return new TlsPSKKeyExchange(keyExchange, pskIdentityManager, dhConfig, ecConfig);
    }

    @Override // com.mi.car.jsse.easysec.tls.TlsKeyExchangeFactory, com.mi.car.jsse.easysec.tls.AbstractTlsKeyExchangeFactory
    public TlsKeyExchange createRSAKeyExchange(int keyExchange) throws IOException {
        return new TlsRSAKeyExchange(keyExchange);
    }

    @Override // com.mi.car.jsse.easysec.tls.TlsKeyExchangeFactory, com.mi.car.jsse.easysec.tls.AbstractTlsKeyExchangeFactory
    public TlsKeyExchange createSRPKeyExchangeClient(int keyExchange, TlsSRPIdentity srpIdentity, TlsSRPConfigVerifier srpConfigVerifier) throws IOException {
        return new TlsSRPKeyExchange(keyExchange, srpIdentity, srpConfigVerifier);
    }

    @Override // com.mi.car.jsse.easysec.tls.TlsKeyExchangeFactory, com.mi.car.jsse.easysec.tls.AbstractTlsKeyExchangeFactory
    public TlsKeyExchange createSRPKeyExchangeServer(int keyExchange, TlsSRPLoginParameters loginParameters) throws IOException {
        return new TlsSRPKeyExchange(keyExchange, loginParameters);
    }
}
