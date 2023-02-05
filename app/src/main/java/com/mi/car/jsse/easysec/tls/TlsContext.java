package com.mi.car.jsse.easysec.tls;

import com.mi.car.jsse.easysec.tls.crypto.TlsCrypto;
import com.mi.car.jsse.easysec.tls.crypto.TlsNonceGenerator;

public interface TlsContext {
    byte[] exportChannelBinding(int i);

    byte[] exportEarlyKeyingMaterial(String str, byte[] bArr, int i);

    byte[] exportKeyingMaterial(String str, byte[] bArr, int i);

    ProtocolVersion[] getClientSupportedVersions();

    ProtocolVersion getClientVersion();

    TlsCrypto getCrypto();

    TlsNonceGenerator getNonceGenerator();

    ProtocolVersion getRSAPreMasterSecretVersion();

    TlsSession getResumableSession();

    SecurityParameters getSecurityParameters();

    SecurityParameters getSecurityParametersConnection();

    SecurityParameters getSecurityParametersHandshake();

    ProtocolVersion getServerVersion();

    TlsSession getSession();

    Object getUserObject();

    boolean isServer();

    void setUserObject(Object obj);
}
