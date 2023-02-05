package com.mi.car.jsse.easysec.jsse.provider;

import java.security.KeyStore;

/* access modifiers changed from: package-private */
public class KeyStoreConfig {
    final KeyStore keyStore;
    final char[] password;

    KeyStoreConfig(KeyStore keyStore2, char[] password2) {
        this.keyStore = keyStore2;
        this.password = password2;
    }
}
