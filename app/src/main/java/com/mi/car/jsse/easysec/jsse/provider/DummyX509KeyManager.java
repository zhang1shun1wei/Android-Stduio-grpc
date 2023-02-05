package com.mi.car.jsse.easysec.jsse.provider;

import com.mi.car.jsse.easysec.jsse.BCX509ExtendedKeyManager;
import com.mi.car.jsse.easysec.jsse.BCX509Key;
import java.net.Socket;
import java.security.Principal;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;

/* access modifiers changed from: package-private */
public final class DummyX509KeyManager extends BCX509ExtendedKeyManager {
    static final BCX509ExtendedKeyManager INSTANCE = new DummyX509KeyManager();

    private DummyX509KeyManager() {
    }

    public String chooseClientAlias(String[] keyType, Principal[] issuers, Socket socket) {
        return null;
    }

    public String chooseServerAlias(String keyType, Principal[] issuers, Socket socket) {
        return null;
    }

    public X509Certificate[] getCertificateChain(String alias) {
        return null;
    }

    public String[] getClientAliases(String keyType, Principal[] issuers) {
        return null;
    }

    public PrivateKey getPrivateKey(String alias) {
        return null;
    }

    public String[] getServerAliases(String keyType, Principal[] issuers) {
        return null;
    }

    /* access modifiers changed from: protected */
    @Override // com.mi.car.jsse.easysec.jsse.BCX509ExtendedKeyManager
    public BCX509Key getKeyBC(String keyType, String alias) {
        return null;
    }
}
