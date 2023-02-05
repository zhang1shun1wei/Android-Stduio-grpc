package com.mi.car.jsse.easysec.jsse.provider;

import com.mi.car.jsse.easysec.jsse.BCX509ExtendedKeyManager;
import com.mi.car.jsse.easysec.jsse.BCX509Key;
import java.net.Socket;
import java.security.Principal;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import javax.net.ssl.X509KeyManager;

/* access modifiers changed from: package-private */
public final class ImportX509KeyManager_4 extends BCX509ExtendedKeyManager implements ImportX509KeyManager {
    final X509KeyManager x509KeyManager;

    ImportX509KeyManager_4(X509KeyManager x509KeyManager2) {
        this.x509KeyManager = x509KeyManager2;
    }

    @Override // com.mi.car.jsse.easysec.jsse.provider.ImportX509KeyManager
    public X509KeyManager unwrap() {
        return this.x509KeyManager;
    }

    public String chooseClientAlias(String[] keyType, Principal[] issuers, Socket socket) {
        return this.x509KeyManager.chooseClientAlias(keyType, issuers, socket);
    }

    public String chooseServerAlias(String keyType, Principal[] issuers, Socket socket) {
        return this.x509KeyManager.chooseServerAlias(keyType, issuers, socket);
    }

    public X509Certificate[] getCertificateChain(String alias) {
        return this.x509KeyManager.getCertificateChain(alias);
    }

    public String[] getClientAliases(String keyType, Principal[] issuers) {
        return this.x509KeyManager.getClientAliases(keyType, issuers);
    }

    public PrivateKey getPrivateKey(String alias) {
        return this.x509KeyManager.getPrivateKey(alias);
    }

    public String[] getServerAliases(String keyType, Principal[] issuers) {
        return this.x509KeyManager.getServerAliases(keyType, issuers);
    }

    /* access modifiers changed from: protected */
    @Override // com.mi.car.jsse.easysec.jsse.BCX509ExtendedKeyManager
    public BCX509Key getKeyBC(String keyType, String alias) {
        return ProvX509Key.from(this.x509KeyManager, keyType, alias);
    }

    /* access modifiers changed from: protected */
    @Override // com.mi.car.jsse.easysec.jsse.BCX509ExtendedKeyManager
    public BCX509Key validateKeyBC(boolean forServer, String keyType, String alias, Socket socket) {
        return ProvX509Key.validate(this.x509KeyManager, forServer, keyType, alias, TransportData.from(socket));
    }
}
