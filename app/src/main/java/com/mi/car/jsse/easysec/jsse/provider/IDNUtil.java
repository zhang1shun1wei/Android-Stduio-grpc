package com.mi.car.jsse.easysec.jsse.provider;

import com.mi.car.jsse.easysec.tls.CipherSuite;
import java.lang.reflect.Method;

public class IDNUtil {
    public static final int ALLOW_UNASSIGNED = ReflectionUtil.getStaticIntOrDefault("java.net.IDN", "ALLOW_UNASSIGNED", 1);
    public static final int USE_STD3_ASCII_RULES = ReflectionUtil.getStaticIntOrDefault("java.net.IDN", "USE_STD3_ASCII_RULES", 2);
    private static final Method toASCIIMethod;
    private static final Method toUnicodeMethod;
    private static final String IDN_CLASSNAME = "java.net.IDN";
    private static final int MAX_LABEL_LENGTH = 63;

    public IDNUtil() {
    }

    public static String toASCII(String input, int flag) {
        if (null != toASCIIMethod) {
            return (String)ReflectionUtil.invokeMethod((Object)null, toASCIIMethod, new Object[]{input, flag});
        } else if (isRoot(input)) {
            return ".";
        } else {
            StringBuilder result = new StringBuilder();
            int len = input.length();

            int sepPos;
            for(int pos = 0; pos < len; pos = sepPos + 1) {
                sepPos = findSeparator(input, pos);
                String label = input.substring(pos, sepPos);
                String asciiLabel = toAsciiLabel(label, flag);
                result.append(asciiLabel);
                if (sepPos < input.length()) {
                    result.append('.');
                }
            }

            return result.toString();
        }
    }

    public static String toUnicode(String input, int flag) {
        if (null != toUnicodeMethod) {
            return (String)ReflectionUtil.invokeMethod((Object)null, toUnicodeMethod, new Object[]{input, flag});
        } else if (isRoot(input)) {
            return ".";
        } else {
            StringBuilder result = new StringBuilder();
            int len = input.length();

            int sepPos;
            for(int pos = 0; pos < len; pos = sepPos + 1) {
                sepPos = findSeparator(input, pos);
                String label = input.substring(pos, sepPos);
                String unicodeLabel = toUnicodeLabel(label, flag);
                result.append(unicodeLabel);
                if (sepPos < input.length()) {
                    result.append('.');
                }
            }

            return result.toString();
        }
    }

    private static int findSeparator(String s, int pos) {
        while(pos < s.length() && !isSeparator(s.charAt(pos))) {
            ++pos;
        }

        return pos;
    }

    private static boolean isAllAscii(CharSequence s) {
        for(int i = 0; i < s.length(); ++i) {
            int c = s.charAt(i);
            if (c >= 128) {
                return false;
            }
        }

        return true;
    }

    private static boolean hasAnyNonLDHAscii(CharSequence s) {
        for(int i = 0; i < s.length(); ++i) {
            int ch = s.charAt(i);
            if (0 <= ch && ch <= ',' || '.' <= ch && ch <= '/' || ':' <= ch && ch <= '@' || '[' <= ch && ch <= '`' || '{' <= ch && ch <= 127) {
                return true;
            }
        }

        return false;
    }

    private static boolean isRoot(String s) {
        return s.length() == 1 && isSeparator(s.charAt(0));
    }

    private static boolean isSeparator(char c) {
        switch(c) {
            case '.':
                return true;
            default:
                return false;
        }
    }

    private static String toAsciiLabel(String s, int flag) {
        if (s.length() < 1) {
            throw new IllegalArgumentException("Domain name label cannot be empty");
        } else {
            boolean allAscii = isAllAscii(s);
            if (!allAscii) {
                throw new UnsupportedOperationException("IDN support incomplete");
            } else {
                boolean useSTD3ASCIIRules = (flag & USE_STD3_ASCII_RULES) != 0;
                if (useSTD3ASCIIRules) {
                    if (hasAnyNonLDHAscii(s)) {
                        throw new IllegalArgumentException("Domain name label cannot contain non-LDH characters");
                    }

                    if ('-' == s.charAt(0) || '-' == s.charAt(s.length() - 1)) {
                        throw new IllegalArgumentException("Domain name label cannot begin or end with a hyphen");
                    }
                }

                if (63 < s.length()) {
                    throw new IllegalArgumentException("Domain name label length cannot be more than 63");
                } else {
                    return s;
                }
            }
        }
    }

    private static String toUnicodeLabel(String s, int flag) {
        return s;
    }

    static {
        toASCIIMethod = ReflectionUtil.getMethod("java.net.IDN", "toASCII", new Class[]{String.class, Integer.TYPE});
        toUnicodeMethod = ReflectionUtil.getMethod("java.net.IDN", "toUnicode", new Class[]{String.class, Integer.TYPE});
    }
}
