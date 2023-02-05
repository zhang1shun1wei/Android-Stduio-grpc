package com.mi.car.jsse.easysec.jsse;

import com.mi.car.jsse.easysec.jsse.provider.IDNUtil;
import com.mi.car.jsse.easysec.tls.NameType;
import com.mi.car.jsse.easysec.util.Strings;
import java.util.Locale;
import java.util.regex.Pattern;

public final class BCSNIHostName extends BCSNIServerName {
    private final String hostName;

    public static BCSNIMatcher createSNIMatcher(String regex) {
        if (regex == null) {
            throw new NullPointerException("'regex' cannot be null");
        } else {
            return new BCSNIHostName.BCSNIHostNameMatcher(regex);
        }
    }

    public BCSNIHostName(String hostName) {
        super(0, Strings.toByteArray(hostName = normalizeHostName(hostName)));
        this.hostName = hostName;
    }

    public BCSNIHostName(byte[] utf8Encoding) {
        super(0, utf8Encoding);
        this.hostName = normalizeHostName(Strings.fromUTF8ByteArray(utf8Encoding));
    }

    public String getAsciiName() {
        return this.hostName;
    }

    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        } else if (!(obj instanceof BCSNIHostName)) {
            return false;
        } else {
            BCSNIHostName other = (BCSNIHostName)obj;
            return this.hostName.equalsIgnoreCase(other.hostName);
        }
    }

    public int hashCode() {
        return this.hostName.toUpperCase(Locale.ENGLISH).hashCode();
    }

    public String toString() {
        return "{type=" + NameType.getText((short)0) + ", value=" + this.hostName + "}";
    }

    private static String normalizeHostName(String hostName) {
        if (null == hostName) {
            throw new NullPointerException("'hostName' cannot be null");
        } else {
            hostName = IDNUtil.toASCII(hostName, IDNUtil.USE_STD3_ASCII_RULES);
            if (hostName.length() < 1) {
                throw new IllegalArgumentException("SNI host_name cannot be empty");
            } else if (hostName.endsWith(".")) {
                throw new IllegalArgumentException("SNI host_name cannot end with a separator");
            } else {
                return hostName;
            }
        }
    }

    private static final class BCSNIHostNameMatcher extends BCSNIMatcher {
        private final Pattern pattern;

        BCSNIHostNameMatcher(String regex) {
            super(0);
            this.pattern = Pattern.compile(regex, 2);
        }

        public boolean matches(BCSNIServerName serverName) {
            if (null == serverName) {
                throw new NullPointerException("'serverName' cannot be null");
            } else if (0 != serverName.getType()) {
                return false;
            } else {
                String asciiName;
                try {
                    asciiName = this.getAsciiHostName(serverName);
                } catch (RuntimeException var4) {
                    return false;
                }

                if (this.pattern.matcher(asciiName).matches()) {
                    return true;
                } else {
                    String unicodeName = IDNUtil.toUnicode(asciiName, 0);
                    return !asciiName.equals(unicodeName) && this.pattern.matcher(unicodeName).matches();
                }
            }
        }

        private String getAsciiHostName(BCSNIServerName serverName) {
            return serverName instanceof BCSNIHostName ? ((BCSNIHostName)serverName).getAsciiName() : BCSNIHostName.normalizeHostName(Strings.fromUTF8ByteArray(serverName.getEncoded()));
        }
    }
}
