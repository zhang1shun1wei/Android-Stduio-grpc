package com.mi.car.jsse.easysec.util;

import java.math.BigInteger;
import java.security.AccessControlException;
import java.security.AccessController;
import java.security.PrivilegedAction;
import java.security.Security;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.StringTokenizer;

public class Properties {
    private static final ThreadLocal threadProperties = new ThreadLocal();

    private Properties() {
    }

    public static boolean isOverrideSet(String propertyName) {
        try {
            return isSetTrue(getPropertyValue(propertyName));
        } catch (AccessControlException e) {
            return false;
        }
    }

    public static boolean isOverrideSetTo(String propertyName, boolean isTrue) {
        try {
            String propertyValue = getPropertyValue(propertyName);
            if (isTrue) {
                return isSetTrue(propertyValue);
            }
            return isSetFalse(propertyValue);
        } catch (AccessControlException e) {
            return false;
        }
    }

    public static boolean setThreadOverride(String propertyName, boolean enable) {
        boolean isSet = isOverrideSet(propertyName);
        Map localProps = (Map) threadProperties.get();
        if (localProps == null) {
            localProps = new HashMap();
            threadProperties.set(localProps);
        }
        localProps.put(propertyName, enable ? "true" : "false");
        return isSet;
    }

    public static boolean removeThreadOverride(String propertyName) {
        String p;
        Map localProps = (Map) threadProperties.get();
        if (localProps == null || (p = (String) localProps.remove(propertyName)) == null) {
            return false;
        }
        if (localProps.isEmpty()) {
            threadProperties.remove();
        }
        return "true".equals(Strings.toLowerCase(p));
    }

    public static int asInteger(String propertyName, int defaultValue) {
        String p = getPropertyValue(propertyName);
        if (p != null) {
            return Integer.parseInt(p);
        }
        return defaultValue;
    }

    public static BigInteger asBigInteger(String propertyName) {
        String p = getPropertyValue(propertyName);
        if (p != null) {
            return new BigInteger(p);
        }
        return null;
    }

    public static Set<String> asKeySet(String propertyName) {
        Set<String> set = new HashSet<>();
        String p = getPropertyValue(propertyName);
        if (p != null) {
            StringTokenizer sTok = new StringTokenizer(p, ",");
            while (sTok.hasMoreElements()) {
                set.add(Strings.toLowerCase(sTok.nextToken()).trim());
            }
        }
        return Collections.unmodifiableSet(set);
    }

    public static String getPropertyValue(final String propertyName) {
        String p;
        String val = (String) AccessController.doPrivileged(new PrivilegedAction() {
            /* class com.mi.car.jsse.easysec.util.Properties.AnonymousClass1 */

            @Override // java.security.PrivilegedAction
            public Object run() {
                return Security.getProperty(propertyName);
            }
        });
        if (val != null) {
            return val;
        }
        Map localProps = (Map) threadProperties.get();
        return (localProps == null || (p = (String) localProps.get(propertyName)) == null) ? (String) AccessController.doPrivileged(new PrivilegedAction() {
            /* class com.mi.car.jsse.easysec.util.Properties.AnonymousClass2 */

            @Override // java.security.PrivilegedAction
            public Object run() {
                return System.getProperty(propertyName);
            }
        }) : p;
    }

    private static boolean isSetFalse(String p) {
        if (p == null || p.length() != 5) {
            return false;
        }
        return (p.charAt(0) == 'f' || p.charAt(0) == 'F') && (p.charAt(1) == 'a' || p.charAt(1) == 'A') && ((p.charAt(2) == 'l' || p.charAt(2) == 'L') && ((p.charAt(3) == 's' || p.charAt(3) == 'S') && (p.charAt(4) == 'e' || p.charAt(4) == 'E')));
    }

    private static boolean isSetTrue(String p) {
        if (p == null || p.length() != 4) {
            return false;
        }
        return (p.charAt(0) == 't' || p.charAt(0) == 'T') && (p.charAt(1) == 'r' || p.charAt(1) == 'R') && ((p.charAt(2) == 'u' || p.charAt(2) == 'U') && (p.charAt(3) == 'e' || p.charAt(3) == 'E'));
    }
}
