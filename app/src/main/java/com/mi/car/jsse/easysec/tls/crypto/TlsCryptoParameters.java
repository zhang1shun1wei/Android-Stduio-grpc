package com.mi.car.jsse.easysec.tls.crypto;

import com.mi.car.jsse.easysec.tls.ProtocolVersion;
import com.mi.car.jsse.easysec.tls.SecurityParameters;
import com.mi.car.jsse.easysec.tls.TlsContext;

public class TlsCryptoParameters {
    private final TlsContext context;

    public TlsCryptoParameters(TlsContext context2) {
        this.context = context2;
    }

    public SecurityParameters getSecurityParametersConnection() {
        return this.context.getSecurityParametersConnection();
    }

    public SecurityParameters getSecurityParametersHandshake() {
        return this.context.getSecurityParametersHandshake();
    }

    public ProtocolVersion getClientVersion() {
        return this.context.getClientVersion();
    }

    public ProtocolVersion getRSAPreMasterSecretVersion() {
        return this.context.getRSAPreMasterSecretVersion();
    }

    public ProtocolVersion getServerVersion() {
        return this.context.getServerVersion();
    }

    public boolean isServer() {
        return this.context.isServer();
    }

    public TlsNonceGenerator getNonceGenerator() {
        return this.context.getNonceGenerator();
    }
}
