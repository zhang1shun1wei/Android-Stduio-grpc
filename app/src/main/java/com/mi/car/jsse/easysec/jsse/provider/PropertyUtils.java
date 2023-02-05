package com.mi.car.jsse.easysec.jsse.provider;

import java.security.AccessController;
import java.security.PrivilegedAction;
import java.security.Security;
import java.util.logging.Level;
import java.util.logging.Logger;

/* access modifiers changed from: package-private */
public class PropertyUtils {
    private static final Logger LOG = Logger.getLogger(PropertyUtils.class.getName());

    PropertyUtils() {
    }

    static String getSecurityProperty(final String propertyName) {
        return (String) AccessController.doPrivileged(new PrivilegedAction<String>() {
            /* class com.mi.car.jsse.easysec.jsse.provider.PropertyUtils.AnonymousClass1 */

            @Override // java.security.PrivilegedAction
            public String run() {
                return Security.getProperty(propertyName);
            }
        });
    }

    static String getSystemProperty(final String propertyName) {
        try {
            return (String) AccessController.doPrivileged(new PrivilegedAction<String>() {
                /* class com.mi.car.jsse.easysec.jsse.provider.PropertyUtils.AnonymousClass2 */

                @Override // java.security.PrivilegedAction
                public String run() {
                    return System.getProperty(propertyName);
                }
            });
        } catch (RuntimeException e) {
            LOG.log(Level.WARNING, "Failed to get system property", (Throwable) e);
            return null;
        }
    }

    static boolean getBooleanSecurityProperty(String propertyName, boolean defaultValue) {
        String propertyValue = getSecurityProperty(propertyName);
        if (propertyValue != null) {
            if ("true".equalsIgnoreCase(propertyValue)) {
                LOG.log(Level.INFO, "Found boolean security property [" + propertyName + "]: " + true);
                return true;
            } else if ("false".equalsIgnoreCase(propertyValue)) {
                LOG.log(Level.INFO, "Found boolean security property [" + propertyName + "]: " + false);
                return false;
            } else {
                LOG.log(Level.WARNING, "Unrecognized value for boolean security property [" + propertyName + "]: " + propertyValue);
            }
        }
        LOG.log(Level.FINE, "Boolean security property [" + propertyName + "] defaulted to: " + defaultValue);
        return defaultValue;
    }

    static boolean getBooleanSystemProperty(String propertyName, boolean defaultValue) {
        String propertyValue = getSystemProperty(propertyName);
        if (propertyValue != null) {
            if ("true".equalsIgnoreCase(propertyValue)) {
                LOG.log(Level.INFO, "Found boolean system property [" + propertyName + "]: " + true);
                return true;
            } else if ("false".equalsIgnoreCase(propertyValue)) {
                LOG.log(Level.INFO, "Found boolean system property [" + propertyName + "]: " + false);
                return false;
            } else {
                LOG.log(Level.WARNING, "Unrecognized value for boolean system property [" + propertyName + "]: " + propertyValue);
            }
        }
        LOG.log(Level.FINE, "Boolean system property [" + propertyName + "] defaulted to: " + defaultValue);
        return defaultValue;
    }

    static int getIntegerSystemProperty(String propertyName, int defaultValue, int minimumValue, int maximumValue) {
        String propertyValue = getSystemProperty(propertyName);
        if (propertyValue != null) {
            try {
                int parsedValue = Integer.parseInt(propertyValue);
                if (parsedValue >= minimumValue && parsedValue <= maximumValue) {
                    LOG.log(Level.INFO, "Found integer system property [" + propertyName + "]: " + parsedValue);
                    return parsedValue;
                } else if (LOG.isLoggable(Level.WARNING)) {
                    LOG.log(Level.WARNING, "Out-of-range (" + getRangeString(minimumValue, maximumValue) + ") integer system property [" + propertyName + "]: " + propertyValue);
                }
            } catch (Exception e) {
                LOG.log(Level.WARNING, "Unrecognized value for integer system property [" + propertyName + "]: " + propertyValue);
            }
        }
        LOG.log(Level.FINE, "Integer system property [" + propertyName + "] defaulted to: " + defaultValue);
        return defaultValue;
    }

    static String getSensitiveStringSystemProperty(String propertyName) {
        String propertyValue = getSystemProperty(propertyName);
        if (propertyValue == null) {
            return null;
        }
        LOG.info("Found sensitive string system property [" + propertyName + "]");
        return propertyValue;
    }

    static String getStringSecurityProperty(String propertyName) {
        String propertyValue = getSecurityProperty(propertyName);
        if (propertyValue == null) {
            return null;
        }
        LOG.log(Level.INFO, "Found string security property [" + propertyName + "]: " + propertyValue);
        return propertyValue;
    }

    static String getStringSecurityProperty(String propertyName, String defaultValue) {
        String propertyValue = getSecurityProperty(propertyName);
        if (propertyValue != null) {
            LOG.log(Level.INFO, "Found string security property [" + propertyName + "]: " + propertyValue);
            return propertyValue;
        }
        LOG.log(Level.WARNING, "String security property [" + propertyName + "] defaulted to: " + defaultValue);
        return defaultValue;
    }

    static String getStringSystemProperty(String propertyName) {
        String propertyValue = getSystemProperty(propertyName);
        if (propertyValue == null) {
            return null;
        }
        LOG.log(Level.INFO, "Found string system property [" + propertyName + "]: " + propertyValue);
        return propertyValue;
    }

    static String[] getStringArraySecurityProperty(String propertyName, String defaultValue) {
        return parseStringArray(getStringSecurityProperty(propertyName, defaultValue));
    }

    static String[] getStringArraySystemProperty(String propertyName) {
        return parseStringArray(getStringSystemProperty(propertyName));
    }

    private static String getRangeString(int minimumValue, int maximumValue) {
        StringBuilder sb = new StringBuilder(32);
        if (Integer.MIN_VALUE != minimumValue) {
            sb.append(minimumValue);
            sb.append(" <= ");
        }
        sb.append('x');
        if (Integer.MAX_VALUE != maximumValue) {
            sb.append(" <= ");
            sb.append(maximumValue);
        }
        return sb.toString();
    }

    private static String[] parseStringArray(String propertyValue) {
        int count;
        if (propertyValue == null) {
            return null;
        }
        String[] entries = JsseUtils.stripDoubleQuotes(propertyValue.trim()).split(",");
        String[] result = new String[entries.length];
        int length = entries.length;
        int i = 0;
        int count2 = 0;
        while (i < length) {
            String entry = entries[i].trim();
            if (entry.length() < 1) {
                count = count2;
            } else {
                count = count2 + 1;
                result[count2] = entry;
            }
            i++;
            count2 = count;
        }
        return JsseUtils.resize(result, count2);
    }
}
