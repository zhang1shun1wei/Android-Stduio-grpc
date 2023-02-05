package com.mi.car.jsse.easysec.tls;

import com.mi.car.jsse.easysec.tls.crypto.TlsSecret;
import com.mi.car.jsse.easysec.util.Arrays;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.Hashtable;

public final class SessionParameters {
    private int cipherSuite;
    private short compressionAlgorithm;
    private byte[] encodedServerExtensions;
    private boolean extendedMasterSecret;
    private Certificate localCertificate;
    private TlsSecret masterSecret;
    private ProtocolVersion negotiatedVersion;
    private Certificate peerCertificate;
    private byte[] pskIdentity;
    private byte[] srpIdentity;

    public static final class Builder {
        private int cipherSuite = -1;
        private short compressionAlgorithm = -1;
        private byte[] encodedServerExtensions = null;
        private boolean extendedMasterSecret = false;
        private Certificate localCertificate = null;
        private TlsSecret masterSecret = null;
        private ProtocolVersion negotiatedVersion;
        private Certificate peerCertificate = null;
        private byte[] pskIdentity = null;
        private byte[] srpIdentity = null;

        public SessionParameters build() {
            boolean z;
            boolean z2;
            boolean z3 = true;
            if (this.cipherSuite >= 0) {
                z = true;
            } else {
                z = false;
            }
            validate(z, "cipherSuite");
            if (this.compressionAlgorithm >= 0) {
                z2 = true;
            } else {
                z2 = false;
            }
            validate(z2, "compressionAlgorithm");
            if (this.masterSecret == null) {
                z3 = false;
            }
            validate(z3, "masterSecret");
            return new SessionParameters(this.cipherSuite, this.compressionAlgorithm, this.localCertificate, this.masterSecret, this.negotiatedVersion, this.peerCertificate, this.pskIdentity, this.srpIdentity, this.encodedServerExtensions, this.extendedMasterSecret);
        }

        public Builder setCipherSuite(int cipherSuite2) {
            this.cipherSuite = cipherSuite2;
            return this;
        }

        public Builder setCompressionAlgorithm(short compressionAlgorithm2) {
            this.compressionAlgorithm = compressionAlgorithm2;
            return this;
        }

        public Builder setExtendedMasterSecret(boolean extendedMasterSecret2) {
            this.extendedMasterSecret = extendedMasterSecret2;
            return this;
        }

        public Builder setLocalCertificate(Certificate localCertificate2) {
            this.localCertificate = localCertificate2;
            return this;
        }

        public Builder setMasterSecret(TlsSecret masterSecret2) {
            this.masterSecret = masterSecret2;
            return this;
        }

        public Builder setNegotiatedVersion(ProtocolVersion negotiatedVersion2) {
            this.negotiatedVersion = negotiatedVersion2;
            return this;
        }

        public Builder setPeerCertificate(Certificate peerCertificate2) {
            this.peerCertificate = peerCertificate2;
            return this;
        }

        public Builder setPSKIdentity(byte[] pskIdentity2) {
            this.pskIdentity = pskIdentity2;
            return this;
        }

        public Builder setSRPIdentity(byte[] srpIdentity2) {
            this.srpIdentity = srpIdentity2;
            return this;
        }

        public Builder setServerExtensions(Hashtable serverExtensions) throws IOException {
            if (serverExtensions == null || serverExtensions.isEmpty()) {
                this.encodedServerExtensions = null;
            } else {
                ByteArrayOutputStream buf = new ByteArrayOutputStream();
                TlsProtocol.writeExtensions(buf, serverExtensions);
                this.encodedServerExtensions = buf.toByteArray();
            }
            return this;
        }

        private void validate(boolean condition, String parameter) {
            if (!condition) {
                throw new IllegalStateException("Required session parameter '" + parameter + "' not configured");
            }
        }
    }

    private SessionParameters(int cipherSuite2, short compressionAlgorithm2, Certificate localCertificate2, TlsSecret masterSecret2, ProtocolVersion negotiatedVersion2, Certificate peerCertificate2, byte[] pskIdentity2, byte[] srpIdentity2, byte[] encodedServerExtensions2, boolean extendedMasterSecret2) {
        this.pskIdentity = null;
        this.srpIdentity = null;
        this.cipherSuite = cipherSuite2;
        this.compressionAlgorithm = compressionAlgorithm2;
        this.localCertificate = localCertificate2;
        this.masterSecret = masterSecret2;
        this.negotiatedVersion = negotiatedVersion2;
        this.peerCertificate = peerCertificate2;
        this.pskIdentity = Arrays.clone(pskIdentity2);
        this.srpIdentity = Arrays.clone(srpIdentity2);
        this.encodedServerExtensions = encodedServerExtensions2;
        this.extendedMasterSecret = extendedMasterSecret2;
    }

    public void clear() {
        if (this.masterSecret != null) {
            this.masterSecret.destroy();
        }
    }

    public SessionParameters copy() {
        return new SessionParameters(this.cipherSuite, this.compressionAlgorithm, this.localCertificate, this.masterSecret, this.negotiatedVersion, this.peerCertificate, this.pskIdentity, this.srpIdentity, this.encodedServerExtensions, this.extendedMasterSecret);
    }

    public int getCipherSuite() {
        return this.cipherSuite;
    }

    public short getCompressionAlgorithm() {
        return this.compressionAlgorithm;
    }

    public Certificate getLocalCertificate() {
        return this.localCertificate;
    }

    public TlsSecret getMasterSecret() {
        return this.masterSecret;
    }

    public ProtocolVersion getNegotiatedVersion() {
        return this.negotiatedVersion;
    }

    public Certificate getPeerCertificate() {
        return this.peerCertificate;
    }

    public byte[] getPSKIdentity() {
        return this.pskIdentity;
    }

    public byte[] getSRPIdentity() {
        return this.srpIdentity;
    }

    public boolean isExtendedMasterSecret() {
        return this.extendedMasterSecret;
    }

    public Hashtable readServerExtensions() throws IOException {
        if (this.encodedServerExtensions == null) {
            return null;
        }
        return TlsProtocol.readExtensions(new ByteArrayInputStream(this.encodedServerExtensions));
    }
}
