package com.mi.car.jsse.easysec.jsse.provider;

import com.mi.car.jsse.easysec.jcajce.util.JcaJceHelper;
import com.mi.car.jsse.easysec.jsse.BCX509ExtendedKeyManager;
import javax.net.ssl.X509ExtendedKeyManager;
import javax.net.ssl.X509KeyManager;

/* access modifiers changed from: package-private */
public abstract class X509KeyManagerUtil {
    X509KeyManagerUtil() {
    }

    static X509KeyManager exportX509KeyManager(BCX509ExtendedKeyManager x509KeyManager) {
        if (x509KeyManager instanceof ImportX509KeyManager) {
            return ((ImportX509KeyManager) x509KeyManager).unwrap();
        }
        return x509KeyManager;
    }

    static BCX509ExtendedKeyManager importX509KeyManager(JcaJceHelper helper, X509KeyManager x509KeyManager) {
        if (x509KeyManager instanceof BCX509ExtendedKeyManager) {
            return (BCX509ExtendedKeyManager) x509KeyManager;
        }
        if (x509KeyManager instanceof X509ExtendedKeyManager) {
            return new ImportX509KeyManager_5((X509ExtendedKeyManager) x509KeyManager);
        }
        return new ImportX509KeyManager_4(x509KeyManager);
    }
}
