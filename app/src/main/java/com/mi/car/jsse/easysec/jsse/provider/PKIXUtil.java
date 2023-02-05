package com.mi.car.jsse.easysec.jsse.provider;

import java.security.cert.CertPathBuilder;
import java.security.cert.PKIXBuilderParameters;
import java.security.cert.X509Certificate;
import java.util.Map;

/* access modifiers changed from: package-private */
public abstract class PKIXUtil {
    private static final Class<?> pkixRevocationCheckerClass;

    PKIXUtil() {
    }

    static {
        Class<?> clazz = null;
        try {
            clazz = ReflectionUtil.getClass("java.security.cert.PKIXRevocationChecker");
        } catch (Exception e) {
        }
        pkixRevocationCheckerClass = clazz;
    }

    static void addStatusResponses(CertPathBuilder pkixBuilder, PKIXBuilderParameters pkixParameters, Map<X509Certificate, byte[]> statusResponseMap) {
        if (pkixRevocationCheckerClass != null) {
            JsseUtils_8.addStatusResponses(pkixBuilder, pkixParameters, statusResponseMap);
        }
    }
}
