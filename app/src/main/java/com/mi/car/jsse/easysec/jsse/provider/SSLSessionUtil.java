package com.mi.car.jsse.easysec.jsse.provider;

import com.mi.car.jsse.easysec.jsse.BCExtendedSSLSession;
import java.lang.reflect.Constructor;
import java.lang.reflect.Method;
import javax.net.ssl.SSLSession;

/* access modifiers changed from: package-private */
public abstract class SSLSessionUtil {
    private static final Constructor<? extends SSLSession> exportSSLSessionConstructor;
    private static final Class<?> extendedSSLSessionClass;
    private static final Constructor<? extends BCExtendedSSLSession> importSSLSessionConstructor;

    SSLSessionUtil() {
    }

    static {
        String className;
        String className2;
        Class<?> clazz = null;
        try {
            clazz = ReflectionUtil.getClass("javax.net.ssl.ExtendedSSLSession");
        } catch (Exception e) {
        }
        extendedSSLSessionClass = clazz;
        Constructor<? extends SSLSession> constructor = null;
        try {
            Method[] methods = ReflectionUtil.getMethods("javax.net.ssl.ExtendedSSLSession");
            if (methods != null) {
                if (ReflectionUtil.hasMethod(methods, "getRequestedServerNames")) {
                    className2 = "com.mi.car.jsse.easysec.jsse.provider.ExportSSLSession_8";
                } else {
                    className2 = "com.mi.car.jsse.easysec.jsse.provider.ExportSSLSession_7";
                }
                constructor = ReflectionUtil.getDeclaredConstructor(className2, BCExtendedSSLSession.class);
            }
        } catch (Exception e2) {
        }
        exportSSLSessionConstructor = constructor;
        Constructor<? extends BCExtendedSSLSession> constructor2 = null;
        if (extendedSSLSessionClass != null) {
            try {
                Method[] methods2 = ReflectionUtil.getMethods("javax.net.ssl.ExtendedSSLSession");
                if (methods2 != null) {
                    if (ReflectionUtil.hasMethod(methods2, "getRequestedServerNames")) {
                        className = "com.mi.car.jsse.easysec.jsse.provider.ImportSSLSession_8";
                    } else {
                        className = "com.mi.car.jsse.easysec.jsse.provider.ImportSSLSession_7";
                    }
                    constructor2 = ReflectionUtil.getDeclaredConstructor(className, extendedSSLSessionClass);
                }
            } catch (Exception e3) {
            }
        }
        importSSLSessionConstructor = constructor2;
    }

    static SSLSession exportSSLSession(BCExtendedSSLSession sslSession) {
        if (sslSession instanceof ImportSSLSession) {
            return ((ImportSSLSession) sslSession).unwrap();
        }
        if (exportSSLSessionConstructor != null) {
            try {
                return (SSLSession) exportSSLSessionConstructor.newInstance(sslSession);
            } catch (Exception e) {
            }
        }
        return new ExportSSLSession_5(sslSession);
    }

    static BCExtendedSSLSession importSSLSession(SSLSession sslSession) {
        if (sslSession instanceof BCExtendedSSLSession) {
            return (BCExtendedSSLSession) sslSession;
        }
        if (sslSession instanceof ExportSSLSession) {
            return ((ExportSSLSession) sslSession).unwrap();
        }
        if (importSSLSessionConstructor != null && extendedSSLSessionClass.isInstance(sslSession)) {
            try {
                return (BCExtendedSSLSession) importSSLSessionConstructor.newInstance(sslSession);
            } catch (Exception e) {
            }
        }
        return new ImportSSLSession_5(sslSession);
    }
}
