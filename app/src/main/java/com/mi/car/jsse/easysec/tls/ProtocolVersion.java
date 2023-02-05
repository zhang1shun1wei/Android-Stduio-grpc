package com.mi.car.jsse.easysec.tls;

import com.mi.car.jsse.easysec.util.Strings;
import java.util.Vector;

public final class ProtocolVersion {
    public static final ProtocolVersion SSLv3 = new ProtocolVersion(768, "SSL 3.0");
    public static final ProtocolVersion TLSv10 = new ProtocolVersion(769, "TLS 1.0");
    public static final ProtocolVersion TLSv11 = new ProtocolVersion(770, "TLS 1.1");
    public static final ProtocolVersion TLSv12 = new ProtocolVersion(771, "TLS 1.2");
    public static final ProtocolVersion TLSv13 = new ProtocolVersion(772, "TLS 1.3");
    public static final ProtocolVersion DTLSv10 = new ProtocolVersion(65279, "DTLS 1.0");
    public static final ProtocolVersion DTLSv12 = new ProtocolVersion(65277, "DTLS 1.2");
    static final ProtocolVersion CLIENT_EARLIEST_SUPPORTED_DTLS;
    static final ProtocolVersion CLIENT_EARLIEST_SUPPORTED_TLS;
    static final ProtocolVersion CLIENT_LATEST_SUPPORTED_DTLS;
    static final ProtocolVersion CLIENT_LATEST_SUPPORTED_TLS;
    static final ProtocolVersion SERVER_EARLIEST_SUPPORTED_DTLS;
    static final ProtocolVersion SERVER_EARLIEST_SUPPORTED_TLS;
    static final ProtocolVersion SERVER_LATEST_SUPPORTED_DTLS;
    static final ProtocolVersion SERVER_LATEST_SUPPORTED_TLS;
    private int version;
    private String name;

    public static boolean contains(ProtocolVersion[] versions, ProtocolVersion version) {
        if (versions != null && version != null) {
            for(int i = 0; i < versions.length; ++i) {
                if (version.equals(versions[i])) {
                    return true;
                }
            }
        }

        return false;
    }

    public static ProtocolVersion getEarliestDTLS(ProtocolVersion[] versions) {
        ProtocolVersion earliest = null;
        if (null != versions) {
            for(int i = 0; i < versions.length; ++i) {
                ProtocolVersion next = versions[i];
                if (null != next && next.isDTLS() && (null == earliest || next.getMinorVersion() > earliest.getMinorVersion())) {
                    earliest = next;
                }
            }
        }

        return earliest;
    }

    public static ProtocolVersion getEarliestTLS(ProtocolVersion[] versions) {
        ProtocolVersion earliest = null;
        if (null != versions) {
            for(int i = 0; i < versions.length; ++i) {
                ProtocolVersion next = versions[i];
                if (null != next && next.isTLS() && (null == earliest || next.getMinorVersion() < earliest.getMinorVersion())) {
                    earliest = next;
                }
            }
        }

        return earliest;
    }

    public static ProtocolVersion getLatestDTLS(ProtocolVersion[] versions) {
        ProtocolVersion latest = null;
        if (null != versions) {
            for(int i = 0; i < versions.length; ++i) {
                ProtocolVersion next = versions[i];
                if (null != next && next.isDTLS() && (null == latest || next.getMinorVersion() < latest.getMinorVersion())) {
                    latest = next;
                }
            }
        }

        return latest;
    }

    public static ProtocolVersion getLatestTLS(ProtocolVersion[] versions) {
        ProtocolVersion latest = null;
        if (null != versions) {
            for(int i = 0; i < versions.length; ++i) {
                ProtocolVersion next = versions[i];
                if (null != next && next.isTLS() && (null == latest || next.getMinorVersion() > latest.getMinorVersion())) {
                    latest = next;
                }
            }
        }

        return latest;
    }

    static boolean isSupportedDTLSVersionClient(ProtocolVersion version) {
        return null != version && version.isEqualOrLaterVersionOf(CLIENT_EARLIEST_SUPPORTED_DTLS) && version.isEqualOrEarlierVersionOf(CLIENT_LATEST_SUPPORTED_DTLS);
    }

    static boolean isSupportedDTLSVersionServer(ProtocolVersion version) {
        return null != version && version.isEqualOrLaterVersionOf(SERVER_EARLIEST_SUPPORTED_DTLS) && version.isEqualOrEarlierVersionOf(SERVER_LATEST_SUPPORTED_DTLS);
    }

    static boolean isSupportedTLSVersionClient(ProtocolVersion version) {
        if (null == version) {
            return false;
        } else {
            int fullVersion = version.getFullVersion();
            return fullVersion >= CLIENT_EARLIEST_SUPPORTED_TLS.getFullVersion() && fullVersion <= CLIENT_LATEST_SUPPORTED_TLS.getFullVersion();
        }
    }

    static boolean isSupportedTLSVersionServer(ProtocolVersion version) {
        if (null == version) {
            return false;
        } else {
            int fullVersion = version.getFullVersion();
            return fullVersion >= SERVER_EARLIEST_SUPPORTED_TLS.getFullVersion() && fullVersion <= SERVER_LATEST_SUPPORTED_TLS.getFullVersion();
        }
    }

    private ProtocolVersion(int v, String name) {
        this.version = v & '\uffff';
        this.name = name;
    }

    public ProtocolVersion[] downTo(ProtocolVersion min) {
        if (!this.isEqualOrLaterVersionOf(min)) {
            throw new IllegalArgumentException("'min' must be an equal or earlier version of this one");
        } else {
            Vector result = new Vector();
            result.addElement(this);
            ProtocolVersion current = this;

            while(!current.equals(min)) {
                current = current.getPreviousVersion();
                result.addElement(current);
            }

            ProtocolVersion[] versions = new ProtocolVersion[result.size()];

            for(int i = 0; i < result.size(); ++i) {
                versions[i] = (ProtocolVersion)result.elementAt(i);
            }

            return versions;
        }
    }

    public int getFullVersion() {
        return this.version;
    }

    public int getMajorVersion() {
        return this.version >> 8;
    }

    public int getMinorVersion() {
        return this.version & 255;
    }

    public String getName() {
        return this.name;
    }

    public boolean isDTLS() {
        return this.getMajorVersion() == 254;
    }

    public boolean isSSL() {
        return this == SSLv3;
    }

    public boolean isTLS() {
        return this.getMajorVersion() == 3;
    }

    public ProtocolVersion getEquivalentTLSVersion() {
        switch(this.getMajorVersion()) {
            case 3:
                return this;
            case 254:
                switch(this.getMinorVersion()) {
                    case 253:
                        return TLSv12;
                    case 255:
                        return TLSv11;
                    default:
                        return null;
                }
            default:
                return null;
        }
    }

    public ProtocolVersion getNextVersion() {
        int major = this.getMajorVersion();
        int minor = this.getMinorVersion();
        switch(major) {
            case 3:
                switch(minor) {
                    case 255:
                        return null;
                    default:
                        return get(major, minor + 1);
                }
            case 254:
                switch(minor) {
                    case 0:
                        return null;
                    case 255:
                        return DTLSv12;
                    default:
                        return get(major, minor - 1);
                }
            default:
                return null;
        }
    }

    public ProtocolVersion getPreviousVersion() {
        int major = this.getMajorVersion();
        int minor = this.getMinorVersion();
        switch(major) {
            case 3:
                switch(minor) {
                    case 0:
                        return null;
                    default:
                        return get(major, minor - 1);
                }
            case 254:
                switch(minor) {
                    case 253:
                        return DTLSv10;
                    case 255:
                        return null;
                    default:
                        return get(major, minor + 1);
                }
            default:
                return null;
        }
    }

    public boolean isEarlierVersionOf(ProtocolVersion version) {
        if (null != version && this.getMajorVersion() == version.getMajorVersion()) {
            int diffMinorVersion = this.getMinorVersion() - version.getMinorVersion();
            return this.isDTLS() ? diffMinorVersion > 0 : diffMinorVersion < 0;
        } else {
            return false;
        }
    }

    public boolean isEqualOrEarlierVersionOf(ProtocolVersion version) {
        if (null != version && this.getMajorVersion() == version.getMajorVersion()) {
            int diffMinorVersion = this.getMinorVersion() - version.getMinorVersion();
            return this.isDTLS() ? diffMinorVersion >= 0 : diffMinorVersion <= 0;
        } else {
            return false;
        }
    }

    public boolean isEqualOrLaterVersionOf(ProtocolVersion version) {
        if (null != version && this.getMajorVersion() == version.getMajorVersion()) {
            int diffMinorVersion = this.getMinorVersion() - version.getMinorVersion();
            return this.isDTLS() ? diffMinorVersion <= 0 : diffMinorVersion >= 0;
        } else {
            return false;
        }
    }

    public boolean isLaterVersionOf(ProtocolVersion version) {
        if (null != version && this.getMajorVersion() == version.getMajorVersion()) {
            int diffMinorVersion = this.getMinorVersion() - version.getMinorVersion();
            return this.isDTLS() ? diffMinorVersion < 0 : diffMinorVersion > 0;
        } else {
            return false;
        }
    }

    public boolean equals(Object other) {
        return this == other || other instanceof ProtocolVersion && this.equals((ProtocolVersion)other);
    }

    public boolean equals(ProtocolVersion other) {
        return other != null && this.version == other.version;
    }

    public int hashCode() {
        return this.version;
    }

    public static ProtocolVersion get(int major, int minor) {
        switch(major) {
            case 3:
                switch(minor) {
                    case 0:
                        return SSLv3;
                    case 1:
                        return TLSv10;
                    case 2:
                        return TLSv11;
                    case 3:
                        return TLSv12;
                    case 4:
                        return TLSv13;
                    default:
                        return getUnknownVersion(major, minor, "TLS");
                }
            case 254:
                switch(minor) {
                    case 253:
                        return DTLSv12;
                    case 254:
                        throw new IllegalArgumentException("{0xFE, 0xFE} is a reserved protocol version");
                    case 255:
                        return DTLSv10;
                    default:
                        return getUnknownVersion(major, minor, "DTLS");
                }
            default:
                return getUnknownVersion(major, minor, "UNKNOWN");
        }
    }

    public ProtocolVersion[] only() {
        return new ProtocolVersion[]{this};
    }

    public String toString() {
        return this.name;
    }

    private static void checkUint8(int versionOctet) {
        if (!TlsUtils.isValidUint8(versionOctet)) {
            throw new IllegalArgumentException("'versionOctet' is not a valid octet");
        }
    }

    private static ProtocolVersion getUnknownVersion(int major, int minor, String prefix) {
        checkUint8(major);
        checkUint8(minor);
        int v = major << 8 | minor;
        String hex = Strings.toUpperCase(Integer.toHexString(65536 | v).substring(1));
        return new ProtocolVersion(v, prefix + " 0x" + hex);
    }

    static {
        CLIENT_EARLIEST_SUPPORTED_DTLS = DTLSv10;
        CLIENT_EARLIEST_SUPPORTED_TLS = SSLv3;
        CLIENT_LATEST_SUPPORTED_DTLS = DTLSv12;
        CLIENT_LATEST_SUPPORTED_TLS = TLSv13;
        SERVER_EARLIEST_SUPPORTED_DTLS = DTLSv10;
        SERVER_EARLIEST_SUPPORTED_TLS = SSLv3;
        SERVER_LATEST_SUPPORTED_DTLS = DTLSv12;
        SERVER_LATEST_SUPPORTED_TLS = TLSv13;
    }
}
