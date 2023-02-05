package com.mi.car.jsse.easysec.jsse.provider;

import java.lang.reflect.Method;
import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;

abstract class KeyStoreUtil {
    private static final Method getProtectionAlgorithm = ReflectionUtil.getMethod("java.security.KeyStore$PasswordProtection", "getProtectionAlgorithm", new Class[0]);

    KeyStoreUtil() {
    }

    static Key getKey(KeyStore keyStore, String alias, KeyStore.ProtectionParameter protectionParameter) throws KeyStoreException, NoSuchAlgorithmException, UnrecoverableKeyException {
        if (protectionParameter == null) {
            throw new UnrecoverableKeyException("requested key requires a password");
        } else if (protectionParameter instanceof KeyStore.PasswordProtection) {
            KeyStore.PasswordProtection passwordProtection = (KeyStore.PasswordProtection) protectionParameter;
            if (getProtectionAlgorithm == null || ReflectionUtil.invokeGetter(passwordProtection, getProtectionAlgorithm) == null) {
                return keyStore.getKey(alias, passwordProtection.getPassword());
            }
            throw new KeyStoreException("unsupported password protection algorithm");
        } else {
            throw new UnsupportedOperationException();
        }
    }
}
