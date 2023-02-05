package com.mi.car.jsse.easysec.jsse;

import java.net.Socket;
import java.security.Principal;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.X509ExtendedKeyManager;

public abstract class BCX509ExtendedKeyManager extends X509ExtendedKeyManager {
    /* access modifiers changed from: protected */
    public abstract BCX509Key getKeyBC(String str, String str2);

    public BCX509Key chooseClientKeyBC(String[] keyTypes, Principal[] issuers, Socket socket) {
        BCX509Key key;
        if (keyTypes != null) {
            for (String keyType : keyTypes) {
                String alias = chooseClientAlias(new String[]{keyType}, issuers, socket);
                if (!(alias == null || (key = validateKeyBC(false, keyType, alias, socket)) == null)) {
                    return key;
                }
            }
        }
        return null;
    }

    public BCX509Key chooseEngineClientKeyBC(String[] keyTypes, Principal[] issuers, SSLEngine engine) {
        BCX509Key key;
        if (keyTypes != null) {
            for (String keyType : keyTypes) {
                String alias = chooseEngineClientAlias(new String[]{keyType}, issuers, engine);
                if (!(alias == null || (key = validateKeyBC(false, keyType, alias, engine)) == null)) {
                    return key;
                }
            }
        }
        return null;
    }

    public BCX509Key chooseEngineServerKeyBC(String[] keyTypes, Principal[] issuers, SSLEngine engine) {
        BCX509Key key;
        if (keyTypes != null) {
            for (String keyType : keyTypes) {
                String alias = chooseEngineServerAlias(keyType, issuers, engine);
                if (!(alias == null || (key = validateKeyBC(true, keyType, alias, engine)) == null)) {
                    return key;
                }
            }
        }
        return null;
    }

    public BCX509Key chooseServerKeyBC(String[] keyTypes, Principal[] issuers, Socket socket) {
        BCX509Key key;
        if (keyTypes != null) {
            for (String keyType : keyTypes) {
                String alias = chooseServerAlias(keyType, issuers, socket);
                if (!(alias == null || (key = validateKeyBC(true, keyType, alias, socket)) == null)) {
                    return key;
                }
            }
        }
        return null;
    }

    /* access modifiers changed from: protected */
    public BCX509Key validateKeyBC(boolean forServer, String keyType, String alias, Socket socket) {
        return getKeyBC(keyType, alias);
    }

    /* access modifiers changed from: protected */
    public BCX509Key validateKeyBC(boolean forServer, String keyType, String alias, SSLEngine engine) {
        return getKeyBC(keyType, alias);
    }
}
