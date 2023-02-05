package com.mi.car.jsse.easysec.tls;

import com.mi.car.jsse.easysec.tls.crypto.TlsSecret;
import java.util.Vector;

public class SecurityParameters {
    ProtocolName applicationProtocol = null;
    boolean applicationProtocolSet = false;
    TlsSecret baseKeyClient = null;
    TlsSecret baseKeyServer = null;
    int cipherSuite = 0;
    short[] clientCertTypes = null;
    byte[] clientRandom = null;
    Vector clientServerNames = null;
    Vector clientSigAlgs = null;
    Vector clientSigAlgsCert = null;
    int[] clientSupportedGroups = null;
    final short compressionAlgorithm = 0;
    TlsSecret earlyExporterMasterSecret = null;
    TlsSecret earlySecret = null;
    boolean encryptThenMAC = false;
    int entity = -1;
    TlsSecret exporterMasterSecret = null;
    boolean extendedMasterSecret = false;
    boolean extendedPadding = false;
    TlsSecret handshakeSecret = null;
    int keyExchangeAlgorithm = -1;
    Certificate localCertificate = null;
    byte[] localVerifyData = null;
    TlsSecret masterSecret = null;
    short maxFragmentLength = -1;
    ProtocolVersion negotiatedVersion = null;
    Certificate peerCertificate = null;
    byte[] peerVerifyData = null;
    int prfAlgorithm = -1;
    int prfCryptoHashAlgorithm = -1;
    short prfHashAlgorithm = -1;
    int prfHashLength = -1;
    byte[] pskIdentity = null;
    boolean renegotiating = false;
    boolean secureRenegotiation = false;
    byte[] serverRandom = null;
    Vector serverSigAlgs = null;
    Vector serverSigAlgsCert = null;
    int[] serverSupportedGroups = null;
    byte[] sessionHash = null;
    byte[] sessionID = null;
    byte[] srpIdentity = null;
    int statusRequestVersion = 0;
    byte[] tlsServerEndPoint = null;
    byte[] tlsUnique = null;
    TlsSecret trafficSecretClient = null;
    TlsSecret trafficSecretServer = null;
    boolean truncatedHMac = false;
    int verifyDataLength = -1;

    /* access modifiers changed from: package-private */
    public void clear() {
        this.sessionHash = null;
        this.sessionID = null;
        this.clientCertTypes = null;
        this.clientServerNames = null;
        this.clientSigAlgs = null;
        this.clientSigAlgsCert = null;
        this.clientSupportedGroups = null;
        this.serverSigAlgs = null;
        this.serverSigAlgsCert = null;
        this.serverSupportedGroups = null;
        this.statusRequestVersion = 0;
        this.baseKeyClient = clearSecret(this.baseKeyClient);
        this.baseKeyServer = clearSecret(this.baseKeyServer);
        this.earlyExporterMasterSecret = clearSecret(this.earlyExporterMasterSecret);
        this.earlySecret = clearSecret(this.earlySecret);
        this.exporterMasterSecret = clearSecret(this.exporterMasterSecret);
        this.handshakeSecret = clearSecret(this.handshakeSecret);
        this.masterSecret = clearSecret(this.masterSecret);
    }

    public int getEntity() {
        return this.entity;
    }

    public boolean isRenegotiating() {
        return this.renegotiating;
    }

    public boolean isSecureRenegotiation() {
        return this.secureRenegotiation;
    }

    public int getCipherSuite() {
        return this.cipherSuite;
    }

    public short[] getClientCertTypes() {
        return this.clientCertTypes;
    }

    public Vector getClientServerNames() {
        return this.clientServerNames;
    }

    public Vector getClientSigAlgs() {
        return this.clientSigAlgs;
    }

    public Vector getClientSigAlgsCert() {
        return this.clientSigAlgsCert;
    }

    public int[] getClientSupportedGroups() {
        return this.clientSupportedGroups;
    }

    public Vector getServerSigAlgs() {
        return this.serverSigAlgs;
    }

    public Vector getServerSigAlgsCert() {
        return this.serverSigAlgsCert;
    }

    public int[] getServerSupportedGroups() {
        return this.serverSupportedGroups;
    }

    public short getCompressionAlgorithm() {
        return 0;
    }

    public short getMaxFragmentLength() {
        return this.maxFragmentLength;
    }

    public int getPrfAlgorithm() {
        return this.prfAlgorithm;
    }

    public int getPRFAlgorithm() {
        return this.prfAlgorithm;
    }

    public int getPRFCryptoHashAlgorithm() {
        return this.prfCryptoHashAlgorithm;
    }

    public short getPRFHashAlgorithm() {
        return this.prfHashAlgorithm;
    }

    public int getPRFHashLength() {
        return this.prfHashLength;
    }

    public int getVerifyDataLength() {
        return this.verifyDataLength;
    }

    public TlsSecret getBaseKeyClient() {
        return this.baseKeyClient;
    }

    public TlsSecret getBaseKeyServer() {
        return this.baseKeyServer;
    }

    public TlsSecret getEarlyExporterMasterSecret() {
        return this.earlyExporterMasterSecret;
    }

    public TlsSecret getEarlySecret() {
        return this.earlySecret;
    }

    public TlsSecret getExporterMasterSecret() {
        return this.exporterMasterSecret;
    }

    public TlsSecret getHandshakeSecret() {
        return this.handshakeSecret;
    }

    public TlsSecret getMasterSecret() {
        return this.masterSecret;
    }

    public TlsSecret getTrafficSecretClient() {
        return this.trafficSecretClient;
    }

    public TlsSecret getTrafficSecretServer() {
        return this.trafficSecretServer;
    }

    public byte[] getClientRandom() {
        return this.clientRandom;
    }

    public byte[] getServerRandom() {
        return this.serverRandom;
    }

    public byte[] getSessionHash() {
        return this.sessionHash;
    }

    public byte[] getSessionID() {
        return this.sessionID;
    }

    public byte[] getPSKIdentity() {
        return this.pskIdentity;
    }

    public byte[] getSRPIdentity() {
        return this.srpIdentity;
    }

    public byte[] getTLSServerEndPoint() {
        return this.tlsServerEndPoint;
    }

    public byte[] getTLSUnique() {
        return this.tlsUnique;
    }

    public boolean isEncryptThenMAC() {
        return this.encryptThenMAC;
    }

    public boolean isExtendedMasterSecret() {
        return this.extendedMasterSecret;
    }

    public boolean isExtendedPadding() {
        return this.extendedPadding;
    }

    public boolean isTruncatedHMac() {
        return this.truncatedHMac;
    }

    public ProtocolName getApplicationProtocol() {
        return this.applicationProtocol;
    }

    public boolean isApplicationProtocolSet() {
        return this.applicationProtocolSet;
    }

    public byte[] getLocalVerifyData() {
        return this.localVerifyData;
    }

    public byte[] getPeerVerifyData() {
        return this.peerVerifyData;
    }

    public int getKeyExchangeAlgorithm() {
        return this.keyExchangeAlgorithm;
    }

    public Certificate getLocalCertificate() {
        return this.localCertificate;
    }

    public Certificate getPeerCertificate() {
        return this.peerCertificate;
    }

    public ProtocolVersion getNegotiatedVersion() {
        return this.negotiatedVersion;
    }

    public int getStatusRequestVersion() {
        return this.statusRequestVersion;
    }

    private static TlsSecret clearSecret(TlsSecret secret) {
        if (secret == null) {
            return null;
        }
        secret.destroy();
        return null;
    }
}
