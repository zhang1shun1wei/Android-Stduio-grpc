package com.mi.car.jsse.easysec.jsse.provider;

import com.mi.car.jsse.easysec.jcajce.util.JcaJceHelper;
import com.mi.car.jsse.easysec.jsse.BCX509ExtendedTrustManager;
import java.lang.reflect.Constructor;
import javax.net.ssl.X509TrustManager;

/* access modifiers changed from: package-private */
public abstract class X509TrustManagerUtil {
    private static final Constructor<? extends X509TrustManager> exportX509TrustManagerConstructor;
    private static final Constructor<? extends BCX509ExtendedTrustManager> importX509TrustManagerConstructor;
    private static final Class<?> x509ExtendedTrustManagerClass;

    X509TrustManagerUtil() {
    }

    static {
        Class<?> clazz = null;
        try {
            clazz = ReflectionUtil.getClass("javax.net.ssl.X509ExtendedTrustManager");
        } catch (Exception e) {
        }
        x509ExtendedTrustManagerClass = clazz;
        Constructor<? extends X509TrustManager> constructor = null;
        try {
            if (ReflectionUtil.getMethods("javax.net.ssl.X509ExtendedTrustManager") != null) {
                constructor = ReflectionUtil.getDeclaredConstructor("com.mi.car.jsse.easysec.jsse.provider.ExportX509TrustManager_7", BCX509ExtendedTrustManager.class);
            }
        } catch (Exception e2) {
        }
        exportX509TrustManagerConstructor = constructor;
        Constructor<? extends BCX509ExtendedTrustManager> constructor2 = null;
        if (x509ExtendedTrustManagerClass != null) {
            try {
                constructor2 = ReflectionUtil.getDeclaredConstructor("com.mi.car.jsse.easysec.jsse.provider.ImportX509TrustManager_7", x509ExtendedTrustManagerClass);
            } catch (Exception e3) {
            }
        }
        importX509TrustManagerConstructor = constructor2;
    }

    static X509TrustManager exportX509TrustManager(BCX509ExtendedTrustManager x509TrustManager) {
        if (x509TrustManager instanceof ImportX509TrustManager) {
            return ((ImportX509TrustManager) x509TrustManager).unwrap();
        }
        if (exportX509TrustManagerConstructor != null) {
            try {
                return (X509TrustManager) exportX509TrustManagerConstructor.newInstance(x509TrustManager);
            } catch (Exception e) {
            }
        }
        return new ExportX509TrustManager_5(x509TrustManager);
    }

    static BCX509ExtendedTrustManager importX509TrustManager(boolean isInFipsMode, JcaJceHelper helper, X509TrustManager x509TrustManager) {
        if (x509TrustManager instanceof BCX509ExtendedTrustManager) {
            return (BCX509ExtendedTrustManager) x509TrustManager;
        }
        if (x509TrustManager instanceof ExportX509TrustManager) {
            return ((ExportX509TrustManager) x509TrustManager).unwrap();
        }
        if (importX509TrustManagerConstructor != null && x509ExtendedTrustManagerClass.isInstance(x509TrustManager)) {
            try {
                return (BCX509ExtendedTrustManager) importX509TrustManagerConstructor.newInstance(x509TrustManager);
            } catch (Exception e) {
            }
        }
        return new ImportX509TrustManager_5(isInFipsMode, helper, x509TrustManager);
    }
}
