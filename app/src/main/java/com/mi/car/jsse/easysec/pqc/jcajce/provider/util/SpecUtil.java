package com.mi.car.jsse.easysec.pqc.jcajce.provider.util;

import java.security.AccessController;
import java.security.PrivilegedAction;
import java.security.spec.AlgorithmParameterSpec;

public class SpecUtil {
    private static Object[] NO_ARGS = new Object[0];
    private static Class[] NO_PARAMS = new Class[0];

    public static String getNameFrom(final AlgorithmParameterSpec paramSpec) {
        return (String) AccessController.doPrivileged(new PrivilegedAction() {
            /* class com.mi.car.jsse.easysec.pqc.jcajce.provider.util.SpecUtil.AnonymousClass1 */

            @Override // java.security.PrivilegedAction
            public Object run() {
                try {
                    return paramSpec.getClass().getMethod("getName", SpecUtil.NO_PARAMS).invoke(paramSpec, SpecUtil.NO_ARGS);
                } catch (Exception e) {
                    return null;
                }
            }
        });
    }
}
