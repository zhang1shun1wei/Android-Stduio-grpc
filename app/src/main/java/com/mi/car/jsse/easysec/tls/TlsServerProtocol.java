package com.mi.car.jsse.easysec.tls;

import com.mi.car.jsse.easysec.tls.Certificate;
import com.mi.car.jsse.easysec.tls.OfferedPsks;
import com.mi.car.jsse.easysec.tls.crypto.TlsAgreement;
import com.mi.car.jsse.easysec.tls.crypto.TlsCrypto;
import com.mi.car.jsse.easysec.tls.crypto.TlsDHConfig;
import com.mi.car.jsse.easysec.tls.crypto.TlsECConfig;
import com.mi.car.jsse.easysec.tls.crypto.TlsSecret;
import com.mi.car.jsse.easysec.util.Arrays;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.Hashtable;
import java.util.Vector;

public class TlsServerProtocol extends TlsProtocol {
    protected TlsServer tlsServer = null;
    TlsServerContextImpl tlsServerContext = null;
    protected int[] offeredCipherSuites = null;
    protected TlsKeyExchange keyExchange = null;
    protected CertificateRequest certificateRequest = null;

    public TlsServerProtocol() {
    }

    public TlsServerProtocol(InputStream input, OutputStream output) {
        super(input, output);
    }

    public void accept(TlsServer tlsServer) throws IOException {
        if (tlsServer == null) {
            throw new IllegalArgumentException("'tlsServer' cannot be null");
        } else if (this.tlsServer != null) {
            throw new IllegalStateException("'accept' can only be called once");
        } else {
            this.tlsServer = tlsServer;
            this.tlsServerContext = new TlsServerContextImpl(tlsServer.getCrypto());
            tlsServer.init(this.tlsServerContext);
            tlsServer.notifyCloseHandle(this);
            this.beginHandshake(false);
            if (this.blocking) {
                this.blockForHandshake();
            }

        }
    }

    protected void cleanupHandshake() {
        super.cleanupHandshake();
        this.offeredCipherSuites = null;
        this.keyExchange = null;
        this.certificateRequest = null;
    }

    protected boolean expectCertificateVerifyMessage() {
        if (null == this.certificateRequest) {
            return false;
        } else {
            Certificate clientCertificate = this.tlsServerContext.getSecurityParametersHandshake().getPeerCertificate();
            return null != clientCertificate && !clientCertificate.isEmpty() && (null == this.keyExchange || this.keyExchange.requiresCertificateVerify());
        }
    }

    protected ServerHello generate13HelloRetryRequest(ClientHello clientHello) throws IOException {
        if (this.retryGroup < 0) {
            throw new TlsFatalAlert((short)80);
        } else {
            SecurityParameters securityParameters = this.tlsServerContext.getSecurityParametersHandshake();
            ProtocolVersion serverVersion = securityParameters.getNegotiatedVersion();
            Hashtable serverHelloExtensions = new Hashtable();
            TlsExtensionsUtils.addSupportedVersionsExtensionServer(serverHelloExtensions, serverVersion);
            if (this.retryGroup >= 0) {
                TlsExtensionsUtils.addKeyShareHelloRetryRequest(serverHelloExtensions, this.retryGroup);
            }

            if (null != this.retryCookie) {
                TlsExtensionsUtils.addCookieExtension(serverHelloExtensions, this.retryCookie);
            }

            TlsUtils.checkExtensionData13(serverHelloExtensions, 6, (short)80);
            return new ServerHello(clientHello.getSessionID(), securityParameters.getCipherSuite(), serverHelloExtensions);
        }
    }

    protected ServerHello generate13ServerHello(ClientHello clientHello, HandshakeMessageInput clientHelloMessage, boolean afterHelloRetryRequest) throws IOException {
        SecurityParameters securityParameters = this.tlsServerContext.getSecurityParametersHandshake();
        if (securityParameters.isRenegotiating()) {
            throw new TlsFatalAlert((short)80);
        } else {
            byte[] legacy_session_id = clientHello.getSessionID();
            Hashtable clientHelloExtensions = clientHello.getExtensions();
            if (null == clientHelloExtensions) {
                throw new TlsFatalAlert((short)109);
            } else {
                ProtocolVersion serverVersion = securityParameters.getNegotiatedVersion();
                TlsCrypto crypto = this.tlsServerContext.getCrypto();
                OfferedPsks.SelectedConfig selectedPSK = TlsUtils.selectPreSharedKey(this.tlsServerContext, this.tlsServer, clientHelloExtensions, clientHelloMessage, this.handshakeHash, afterHelloRetryRequest);
                Vector clientShares = TlsExtensionsUtils.getKeyShareClientHello(clientHelloExtensions);
                KeyShareEntry clientShare = null;
                if (afterHelloRetryRequest) {
                    if (this.retryGroup < 0) {
                        throw new TlsFatalAlert((short)80);
                    }

                    if (null == selectedPSK) {
                        if (null == securityParameters.getClientSigAlgs()) {
                            throw new TlsFatalAlert((short)109);
                        }
                    } else if (selectedPSK.psk.getPRFAlgorithm() != securityParameters.getPRFAlgorithm()) {
                        throw new TlsFatalAlert((short)47);
                    }

                    byte[] cookie = TlsExtensionsUtils.getCookieExtension(clientHelloExtensions);
                    if (!Arrays.areEqual(this.retryCookie, cookie)) {
                        throw new TlsFatalAlert((short)47);
                    }

                    this.retryCookie = null;
                    clientShare = TlsUtils.selectKeyShare(clientShares, this.retryGroup);
                    if (null == clientShare) {
                        throw new TlsFatalAlert((short)47);
                    }
                } else {
                    this.clientExtensions = clientHelloExtensions;
                    securityParameters.secureRenegotiation = false;
                    TlsExtensionsUtils.getPaddingExtension(clientHelloExtensions);
                    securityParameters.clientServerNames = TlsExtensionsUtils.getServerNameExtensionClient(clientHelloExtensions);
                    TlsUtils.establishClientSigAlgs(securityParameters, clientHelloExtensions);
                    if (null == selectedPSK && null == securityParameters.getClientSigAlgs()) {
                        throw new TlsFatalAlert((short)109);
                    }

                    this.tlsServer.processClientExtensions(clientHelloExtensions);
                    this.tlsSession = TlsUtils.importSession(TlsUtils.EMPTY_BYTES, (SessionParameters)null);
                    this.sessionParameters = null;
                    this.sessionMasterSecret = null;
                    securityParameters.sessionID = this.tlsSession.getSessionID();
                    this.tlsServer.notifySession(this.tlsSession);
                    TlsUtils.negotiatedVersionTLSServer(this.tlsServerContext);
                    securityParameters.serverRandom = createRandomBlock(false, this.tlsServerContext);
                    if (!serverVersion.equals(ProtocolVersion.getLatestTLS(this.tlsServer.getProtocolVersions()))) {
                        TlsUtils.writeDowngradeMarker(serverVersion, securityParameters.getServerRandom());
                    }

                    int cipherSuite = this.tlsServer.getSelectedCipherSuite();
                    if (!TlsUtils.isValidCipherSuiteSelection(this.offeredCipherSuites, cipherSuite) || !TlsUtils.isValidVersionForCipherSuite(cipherSuite, serverVersion)) {
                        throw new TlsFatalAlert((short)80);
                    }

                    TlsUtils.negotiatedCipherSuite(securityParameters, cipherSuite);
                    int[] clientSupportedGroups = securityParameters.getClientSupportedGroups();
                    int[] serverSupportedGroups = securityParameters.getServerSupportedGroups();
                    clientShare = TlsUtils.selectKeyShare(crypto, serverVersion, clientShares, clientSupportedGroups, serverSupportedGroups);
                    if (null == clientShare) {
                        this.retryGroup = TlsUtils.selectKeyShareGroup(crypto, serverVersion, clientSupportedGroups, serverSupportedGroups);
                        if (this.retryGroup < 0) {
                            throw new TlsFatalAlert((short)40);
                        }

                        this.retryCookie = this.tlsServerContext.getNonceGenerator().generateNonce(16);
                        return this.generate13HelloRetryRequest(clientHello);
                    }

                    if (clientShare.getNamedGroup() != serverSupportedGroups[0]) {
                    }
                }

                Hashtable serverHelloExtensions = new Hashtable();
                Hashtable serverEncryptedExtensions = TlsExtensionsUtils.ensureExtensionsInitialised(this.tlsServer.getServerExtensions());
                this.tlsServer.getServerExtensionsForConnection(serverEncryptedExtensions);
                ProtocolVersion serverLegacyVersion = ProtocolVersion.TLSv12;
                TlsExtensionsUtils.addSupportedVersionsExtensionServer(serverHelloExtensions, serverVersion);
                securityParameters.extendedMasterSecret = true;
                securityParameters.applicationProtocol = TlsExtensionsUtils.getALPNExtensionServer(serverEncryptedExtensions);
                securityParameters.applicationProtocolSet = true;
                if (!serverEncryptedExtensions.isEmpty()) {
                    securityParameters.maxFragmentLength = this.processMaxFragmentLengthExtension(clientHelloExtensions, serverEncryptedExtensions, (short)80);
                }

                securityParameters.encryptThenMAC = false;
                securityParameters.truncatedHMac = false;
                securityParameters.statusRequestVersion = clientHelloExtensions.containsKey(TlsExtensionsUtils.EXT_status_request) ? 1 : 0;
                this.expectSessionTicket = false;
                TlsSecret pskEarlySecret = null;
                if (null != selectedPSK) {
                    pskEarlySecret = selectedPSK.earlySecret;
                    this.selectedPSK13 = true;
                    TlsExtensionsUtils.addPreSharedKeyServerHello(serverHelloExtensions, selectedPSK.index);
                }

                int namedGroup = clientShare.getNamedGroup();
                TlsAgreement agreement;
                if (NamedGroup.refersToASpecificCurve(namedGroup)) {
                    agreement = crypto.createECDomain(new TlsECConfig(namedGroup)).createECDH();
                } else {
                    if (!NamedGroup.refersToASpecificFiniteField(namedGroup)) {
                        throw new TlsFatalAlert((short)80);
                    }

                    agreement = crypto.createDHDomain(new TlsDHConfig(namedGroup, true)).createDH();
                }

                byte[] key_exchange = agreement.generateEphemeral();
                KeyShareEntry serverShare = new KeyShareEntry(namedGroup, key_exchange);
                TlsExtensionsUtils.addKeyShareServerHello(serverHelloExtensions, serverShare);
                agreement.receivePeerValue(clientShare.getKeyExchange());
                TlsSecret sharedSecret = agreement.calculateSecret();
                TlsUtils.establish13PhaseSecrets(this.tlsServerContext, pskEarlySecret, sharedSecret);
                this.serverExtensions = serverEncryptedExtensions;
                this.applyMaxFragmentLengthExtension(securityParameters.getMaxFragmentLength());
                TlsUtils.checkExtensionData13(serverHelloExtensions, 2, (short)80);
                return new ServerHello(serverLegacyVersion, securityParameters.getServerRandom(), legacy_session_id, securityParameters.getCipherSuite(), serverHelloExtensions);
            }
        }
    }

    protected ServerHello generateServerHello(ClientHello clientHello, HandshakeMessageInput clientHelloMessage) throws IOException {
        ProtocolVersion clientLegacyVersion = clientHello.getVersion();
        if (!clientLegacyVersion.isTLS()) {
            throw new TlsFatalAlert((short)47);
        } else {
            this.offeredCipherSuites = clientHello.getCipherSuites();
            SecurityParameters securityParameters = this.tlsServerContext.getSecurityParametersHandshake();
            this.tlsServerContext.setClientSupportedVersions(TlsExtensionsUtils.getSupportedVersionsExtensionClient(clientHello.getExtensions()));
            ProtocolVersion clientVersion = clientLegacyVersion;
            if (null == this.tlsServerContext.getClientSupportedVersions()) {
                if (clientLegacyVersion.isLaterVersionOf(ProtocolVersion.TLSv12)) {
                    clientVersion = ProtocolVersion.TLSv12;
                }

                this.tlsServerContext.setClientSupportedVersions(clientVersion.downTo(ProtocolVersion.SSLv3));
            } else {
                clientVersion = ProtocolVersion.getLatestTLS(this.tlsServerContext.getClientSupportedVersions());
            }

            this.recordStream.setWriteVersion(clientVersion);
            if (!ProtocolVersion.SERVER_EARLIEST_SUPPORTED_TLS.isEqualOrEarlierVersionOf(clientVersion)) {
                throw new TlsFatalAlert((short)70);
            } else {
                if (securityParameters.isRenegotiating()) {
                    if (!clientVersion.equals(this.tlsServerContext.getClientVersion()) && !clientVersion.equals(this.tlsServerContext.getServerVersion())) {
                        throw new TlsFatalAlert((short)47);
                    }
                } else {
                    this.tlsServerContext.setClientVersion(clientVersion);
                }

                this.tlsServer.notifyClientVersion(this.tlsServerContext.getClientVersion());
                securityParameters.clientRandom = clientHello.getRandom();
                this.tlsServer.notifyFallback(Arrays.contains(this.offeredCipherSuites, 22016));
                this.tlsServer.notifyOfferedCipherSuites(this.offeredCipherSuites);
                ProtocolVersion serverVersion;
                if (securityParameters.isRenegotiating()) {
                    serverVersion = this.tlsServerContext.getServerVersion();
                } else {
                    serverVersion = this.tlsServer.getServerVersion();
                    if (!ProtocolVersion.contains(this.tlsServerContext.getClientSupportedVersions(), serverVersion)) {
                        throw new TlsFatalAlert((short)80);
                    }

                    securityParameters.negotiatedVersion = serverVersion;
                }

                securityParameters.clientSupportedGroups = TlsExtensionsUtils.getSupportedGroupsExtension(clientHello.getExtensions());
                securityParameters.serverSupportedGroups = this.tlsServer.getSupportedGroups();
                if (ProtocolVersion.TLSv13.isEqualOrEarlierVersionOf(serverVersion)) {
                    this.recordStream.setIgnoreChangeCipherSpec(true);
                    this.recordStream.setWriteVersion(ProtocolVersion.TLSv12);
                    return this.generate13ServerHello(clientHello, clientHelloMessage, false);
                } else {
                    this.recordStream.setWriteVersion(serverVersion);
                    this.clientExtensions = clientHello.getExtensions();
                    byte[] clientRenegExtData = TlsUtils.getExtensionData(this.clientExtensions, EXT_RenegotiationInfo);
                    byte[] serverRenegExtData;
                    if (securityParameters.isRenegotiating()) {
                        if (!securityParameters.isSecureRenegotiation()) {
                            throw new TlsFatalAlert((short)80);
                        }

                        if (Arrays.contains(this.offeredCipherSuites, 255)) {
                            throw new TlsFatalAlert((short)40);
                        }

                        if (null == clientRenegExtData) {
                            throw new TlsFatalAlert((short)40);
                        }

                        SecurityParameters saved = this.tlsServerContext.getSecurityParametersConnection();
                        serverRenegExtData = saved.getPeerVerifyData();
                        if (!Arrays.constantTimeAreEqual(clientRenegExtData, createRenegotiationInfo(serverRenegExtData))) {
                            throw new TlsFatalAlert((short)40);
                        }
                    } else {
                        if (Arrays.contains(this.offeredCipherSuites, 255)) {
                            securityParameters.secureRenegotiation = true;
                        }

                        if (clientRenegExtData != null) {
                            securityParameters.secureRenegotiation = true;
                            if (!Arrays.constantTimeAreEqual(clientRenegExtData, createRenegotiationInfo(TlsUtils.EMPTY_BYTES))) {
                                throw new TlsFatalAlert((short)40);
                            }
                        }
                    }

                    this.tlsServer.notifySecureRenegotiation(securityParameters.isSecureRenegotiation());
                    boolean offeredExtendedMasterSecret = TlsExtensionsUtils.hasExtendedMasterSecretExtension(this.clientExtensions);
                    if (this.clientExtensions != null) {
                        TlsExtensionsUtils.getPaddingExtension(this.clientExtensions);
                        securityParameters.clientServerNames = TlsExtensionsUtils.getServerNameExtensionClient(this.clientExtensions);
                        if (TlsUtils.isSignatureAlgorithmsExtensionAllowed(clientVersion)) {
                            TlsUtils.establishClientSigAlgs(securityParameters, this.clientExtensions);
                        }

                        securityParameters.clientSupportedGroups = TlsExtensionsUtils.getSupportedGroupsExtension(this.clientExtensions);
                        this.tlsServer.processClientExtensions(this.clientExtensions);
                    }

                    this.resumedSession = this.establishSession(this.tlsServer.getSessionToResume(clientHello.getSessionID()));
                    if (!this.resumedSession) {
                        serverRenegExtData = this.tlsServer.getNewSessionID();
                        if (null == serverRenegExtData) {
                            serverRenegExtData = TlsUtils.EMPTY_BYTES;
                        }

                        this.tlsSession = TlsUtils.importSession(serverRenegExtData, (SessionParameters)null);
                        this.sessionParameters = null;
                        this.sessionMasterSecret = null;
                    }

                    securityParameters.sessionID = this.tlsSession.getSessionID();
                    this.tlsServer.notifySession(this.tlsSession);
                    TlsUtils.negotiatedVersionTLSServer(this.tlsServerContext);
                    boolean useGMTUnixTime = this.tlsServer.shouldUseGMTUnixTime();
                    securityParameters.serverRandom = createRandomBlock(useGMTUnixTime, this.tlsServerContext);
                    if (!serverVersion.equals(ProtocolVersion.getLatestTLS(this.tlsServer.getProtocolVersions()))) {
                        TlsUtils.writeDowngradeMarker(serverVersion, securityParameters.getServerRandom());
                    }

                    int cipherSuite = this.resumedSession ? this.sessionParameters.getCipherSuite() : this.tlsServer.getSelectedCipherSuite();
                    if (TlsUtils.isValidCipherSuiteSelection(this.offeredCipherSuites, cipherSuite) && TlsUtils.isValidVersionForCipherSuite(cipherSuite, serverVersion)) {
                        TlsUtils.negotiatedCipherSuite(securityParameters, cipherSuite);
                        this.tlsServerContext.setRSAPreMasterSecretVersion(clientLegacyVersion);
                        Hashtable sessionServerExtensions = this.resumedSession ? this.sessionParameters.readServerExtensions() : this.tlsServer.getServerExtensions();
                        this.serverExtensions = TlsExtensionsUtils.ensureExtensionsInitialised(sessionServerExtensions);
                        this.tlsServer.getServerExtensionsForConnection(this.serverExtensions);
                        if (securityParameters.isRenegotiating()) {
                            if (!securityParameters.isSecureRenegotiation()) {
                                throw new TlsFatalAlert((short)80);
                            }

                            SecurityParameters saved = this.tlsServerContext.getSecurityParametersConnection();
                            byte[] reneg_conn_info = TlsUtils.concat(saved.getPeerVerifyData(), saved.getLocalVerifyData());
                            this.serverExtensions.put(EXT_RenegotiationInfo, createRenegotiationInfo(reneg_conn_info));
                        } else if (securityParameters.isSecureRenegotiation()) {
                            serverRenegExtData = TlsUtils.getExtensionData(this.serverExtensions, EXT_RenegotiationInfo);
                            boolean noRenegExt = null == serverRenegExtData;
                            if (noRenegExt) {
                                this.serverExtensions.put(EXT_RenegotiationInfo, createRenegotiationInfo(TlsUtils.EMPTY_BYTES));
                            }
                        }

                        if (this.resumedSession) {
                            if (!this.sessionParameters.isExtendedMasterSecret()) {
                                throw new TlsFatalAlert((short)80);
                            }

                            if (!offeredExtendedMasterSecret) {
                                throw new TlsFatalAlert((short)40);
                            }

                            securityParameters.extendedMasterSecret = true;
                            TlsExtensionsUtils.addExtendedMasterSecretExtension(this.serverExtensions);
                        } else {
                            securityParameters.extendedMasterSecret = offeredExtendedMasterSecret && !serverVersion.isSSL() && this.tlsServer.shouldUseExtendedMasterSecret();
                            if (securityParameters.isExtendedMasterSecret()) {
                                TlsExtensionsUtils.addExtendedMasterSecretExtension(this.serverExtensions);
                            } else if (this.tlsServer.requiresExtendedMasterSecret()) {
                                throw new TlsFatalAlert((short)40);
                            }
                        }

                        securityParameters.applicationProtocol = TlsExtensionsUtils.getALPNExtensionServer(this.serverExtensions);
                        securityParameters.applicationProtocolSet = true;
                        if (!this.serverExtensions.isEmpty()) {
                            securityParameters.encryptThenMAC = TlsExtensionsUtils.hasEncryptThenMACExtension(this.serverExtensions);
                            securityParameters.maxFragmentLength = this.processMaxFragmentLengthExtension(this.clientExtensions, this.serverExtensions, (short)80);
                            securityParameters.truncatedHMac = TlsExtensionsUtils.hasTruncatedHMacExtension(this.serverExtensions);
                            if (!this.resumedSession) {
                                if (TlsUtils.hasExpectedEmptyExtensionData(this.serverExtensions, TlsExtensionsUtils.EXT_status_request_v2, (short)80)) {
                                    securityParameters.statusRequestVersion = 2;
                                } else if (TlsUtils.hasExpectedEmptyExtensionData(this.serverExtensions, TlsExtensionsUtils.EXT_status_request, (short)80)) {
                                    securityParameters.statusRequestVersion = 1;
                                }

                                this.expectSessionTicket = TlsUtils.hasExpectedEmptyExtensionData(this.serverExtensions, EXT_SessionTicket, (short)80);
                            }
                        }

                        this.applyMaxFragmentLengthExtension(securityParameters.getMaxFragmentLength());
                        return new ServerHello(serverVersion, securityParameters.getServerRandom(), this.tlsSession.getSessionID(), securityParameters.getCipherSuite(), this.serverExtensions);
                    } else {
                        throw new TlsFatalAlert((short)80);
                    }
                }
            }
        }
    }

    protected TlsContext getContext() {
        return this.tlsServerContext;
    }

    AbstractTlsContext getContextAdmin() {
        return this.tlsServerContext;
    }

    protected TlsPeer getPeer() {
        return this.tlsServer;
    }

    protected void handle13HandshakeMessage(short type, HandshakeMessageInput buf) throws IOException {
        if (!this.isTLSv13ConnectionState()) {
            throw new TlsFatalAlert((short)80);
        } else if (this.resumedSession) {
            throw new TlsFatalAlert((short)80);
        } else {
            switch(type) {
                case 0:
                case 2:
                case 3:
                case 4:
                case 5:
                case 8:
                case 12:
                case 13:
                case 14:
                case 16:
                case 21:
                case 22:
                case 23:
                case 25:
                case 254:
                default:
                    throw new TlsFatalAlert((short)10);
                case 1:
                    switch(this.connection_state) {
                        case 0:
                            throw new TlsFatalAlert((short)80);
                        case 2:
                            ClientHello clientHelloRetry = this.receiveClientHelloMessage(buf);
                            this.connection_state = 3;
                            ServerHello serverHello = this.generate13ServerHello(clientHelloRetry, buf, true);
                            this.sendServerHelloMessage(serverHello);
                            this.connection_state = 4;
                            this.send13ServerHelloCoda(serverHello, true);
                            return;
                        default:
                            throw new TlsFatalAlert((short)10);
                    }
                case 11:
                    switch(this.connection_state) {
                        case 20:
                            this.receive13ClientCertificate(buf);
                            this.connection_state = 15;
                            return;
                        default:
                            throw new TlsFatalAlert((short)10);
                    }
                case 15:
                    switch(this.connection_state) {
                        case 15:
                            this.receive13ClientCertificateVerify(buf);
                            buf.updateHash(this.handshakeHash);
                            this.connection_state = 17;
                            return;
                        default:
                            throw new TlsFatalAlert((short)10);
                    }
                case 20:
                    switch(this.connection_state) {
                        case 20:
                            this.skip13ClientCertificate();
                        case 15:
                            this.skip13ClientCertificateVerify();
                        case 17:
                            this.receive13ClientFinished(buf);
                            this.connection_state = 18;
                            this.recordStream.setIgnoreChangeCipherSpec(false);
                            this.recordStream.enablePendingCipherRead(false);
                            this.completeHandshake();
                            return;
                        default:
                            throw new TlsFatalAlert((short)10);
                    }
                case 24:
                    this.receive13KeyUpdate(buf);
            }
        }
    }

    protected void handleHandshakeMessage(short type, HandshakeMessageInput buf) throws IOException {
        SecurityParameters securityParameters = this.tlsServerContext.getSecurityParameters();
        if (this.connection_state > 1 && TlsUtils.isTLSv13(securityParameters.getNegotiatedVersion())) {
            this.handle13HandshakeMessage(type, buf);
        } else if (!this.isLegacyConnectionState()) {
            throw new TlsFatalAlert((short)80);
        } else if (this.resumedSession) {
            if (type == 20 && this.connection_state == 20) {
                this.processFinishedMessage(buf);
                this.connection_state = 18;
                this.completeHandshake();
            } else {
                throw new TlsFatalAlert((short)10);
            }
        } else {
            switch(type) {
                case 0:
                case 2:
                case 3:
                case 4:
                case 5:
                case 8:
                case 12:
                case 13:
                case 14:
                case 21:
                case 22:
                case 24:
                case 25:
                case 254:
                default:
                    throw new TlsFatalAlert((short)10);
                case 1:
                    if (this.isApplicationDataReady()) {
                        if (!this.handleRenegotiation()) {
                            break;
                        }

                        this.connection_state = 0;
                    }

                    switch(this.connection_state) {
                        case 0:
                            ClientHello clientHello = this.receiveClientHelloMessage(buf);
                            this.connection_state = 1;
                            ServerHello serverHello = this.generateServerHello(clientHello, buf);
                            this.handshakeHash.notifyPRFDetermined();
                            if (TlsUtils.isTLSv13(securityParameters.getNegotiatedVersion())) {
                                this.handshakeHash.sealHashAlgorithms();
                                if (serverHello.isHelloRetryRequest()) {
                                    TlsUtils.adjustTranscriptForRetry(this.handshakeHash);
                                    this.sendServerHelloMessage(serverHello);
                                    this.connection_state = 2;
                                    this.sendChangeCipherSpecMessage();
                                } else {
                                    this.sendServerHelloMessage(serverHello);
                                    this.connection_state = 4;
                                    this.sendChangeCipherSpecMessage();
                                    this.send13ServerHelloCoda(serverHello, false);
                                }

                                return;
                            } else {
                                buf.updateHash(this.handshakeHash);
                                this.sendServerHelloMessage(serverHello);
                                this.connection_state = 4;
                                if (this.resumedSession) {
                                    securityParameters.masterSecret = this.sessionMasterSecret;
                                    this.recordStream.setPendingCipher(TlsUtils.initCipher(this.tlsServerContext));
                                    this.sendChangeCipherSpec();
                                    this.sendFinishedMessage();
                                    this.connection_state = 20;
                                } else {
                                    Vector serverSupplementalData = this.tlsServer.getServerSupplementalData();
                                    if (serverSupplementalData != null) {
                                        this.sendSupplementalDataMessage(serverSupplementalData);
                                        this.connection_state = 6;
                                    }

                                    this.keyExchange = TlsUtils.initKeyExchangeServer(this.tlsServerContext, this.tlsServer);
                                    TlsCredentials serverCredentials = TlsUtils.establishServerCredentials(this.tlsServer);
                                    Certificate serverCertificate = null;
                                    ByteArrayOutputStream endPointHash = new ByteArrayOutputStream();
                                    if (null == serverCredentials) {
                                        this.keyExchange.skipServerCredentials();
                                    } else {
                                        this.keyExchange.processServerCredentials(serverCredentials);
                                        serverCertificate = serverCredentials.getCertificate();
                                        this.sendCertificateMessage(serverCertificate, endPointHash);
                                        this.connection_state = 7;
                                    }

                                    securityParameters.tlsServerEndPoint = endPointHash.toByteArray();
                                    if (null == serverCertificate || serverCertificate.isEmpty()) {
                                        securityParameters.statusRequestVersion = 0;
                                    }

                                    if (securityParameters.getStatusRequestVersion() > 0) {
                                        CertificateStatus certificateStatus = this.tlsServer.getCertificateStatus();
                                        if (certificateStatus != null) {
                                            this.sendCertificateStatusMessage(certificateStatus);
                                            this.connection_state = 8;
                                        }
                                    }

                                    byte[] serverKeyExchange = this.keyExchange.generateServerKeyExchange();
                                    if (serverKeyExchange != null) {
                                        this.sendServerKeyExchangeMessage(serverKeyExchange);
                                        this.connection_state = 10;
                                    }

                                    if (null != serverCredentials) {
                                        this.certificateRequest = this.tlsServer.getCertificateRequest();
                                        if (null == this.certificateRequest) {
                                            if (!this.keyExchange.requiresCertificateVerify()) {
                                                throw new TlsFatalAlert((short)80);
                                            }
                                        } else {
                                            if (TlsUtils.isTLSv12(this.tlsServerContext) != (this.certificateRequest.getSupportedSignatureAlgorithms() != null)) {
                                                throw new TlsFatalAlert((short)80);
                                            }

                                            this.certificateRequest = TlsUtils.validateCertificateRequest(this.certificateRequest, this.keyExchange);
                                            TlsUtils.establishServerSigAlgs(securityParameters, this.certificateRequest);
                                            TlsUtils.trackHashAlgorithms(this.handshakeHash, securityParameters.getServerSigAlgs());
                                            this.sendCertificateRequestMessage(this.certificateRequest);
                                            this.connection_state = 11;
                                        }
                                    }

                                    this.sendServerHelloDoneMessage();
                                    this.connection_state = 12;
                                    boolean forceBuffering = false;
                                    TlsUtils.sealHandshakeHash(this.tlsServerContext, this.handshakeHash, forceBuffering);
                                }

                                return;
                            }
                        case 21:
                            throw new TlsFatalAlert((short)80);
                        default:
                            throw new TlsFatalAlert((short)10);
                    }
                case 11:
                    switch(this.connection_state) {
                        case 12:
                            this.tlsServer.processClientSupplementalData((Vector)null);
                        case 14:
                            this.receiveCertificateMessage(buf);
                            this.connection_state = 15;
                            return;
                        default:
                            throw new TlsFatalAlert((short)10);
                    }
                case 15:
                    switch(this.connection_state) {
                        case 16:
                            if (!this.expectCertificateVerifyMessage()) {
                                throw new TlsFatalAlert((short)10);
                            }

                            this.receiveCertificateVerifyMessage(buf);
                            buf.updateHash(this.handshakeHash);
                            this.connection_state = 17;
                            return;
                        default:
                            throw new TlsFatalAlert((short)10);
                    }
                case 16:
                    switch(this.connection_state) {
                        case 12:
                            this.tlsServer.processClientSupplementalData((Vector)null);
                        case 14:
                            if (null == this.certificateRequest) {
                                this.keyExchange.skipClientCredentials();
                            } else {
                                if (TlsUtils.isTLSv12(this.tlsServerContext)) {
                                    throw new TlsFatalAlert((short)10);
                                }

                                if (TlsUtils.isSSL(this.tlsServerContext)) {
                                    throw new TlsFatalAlert((short)10);
                                }

                                this.notifyClientCertificate(Certificate.EMPTY_CHAIN);
                            }
                        case 15:
                            this.receiveClientKeyExchangeMessage(buf);
                            this.connection_state = 16;
                            return;
                        case 13:
                        default:
                            throw new TlsFatalAlert((short)10);
                    }
                case 20:
                    switch(this.connection_state) {
                        case 16:
                            if (this.expectCertificateVerifyMessage()) {
                                throw new TlsFatalAlert((short)10);
                            }
                        case 17:
                            this.processFinishedMessage(buf);
                            buf.updateHash(this.handshakeHash);
                            this.connection_state = 18;
                            if (this.expectSessionTicket) {
                                this.sendNewSessionTicketMessage(this.tlsServer.getNewSessionTicket());
                                this.connection_state = 19;
                            }

                            this.sendChangeCipherSpec();
                            this.sendFinishedMessage();
                            this.connection_state = 20;
                            this.completeHandshake();
                            return;
                        default:
                            throw new TlsFatalAlert((short)10);
                    }
                case 23:
                    switch(this.connection_state) {
                        case 12:
                            this.tlsServer.processClientSupplementalData(readSupplementalDataMessage(buf));
                            this.connection_state = 14;
                            break;
                        default:
                            throw new TlsFatalAlert((short)10);
                    }
            }

        }
    }

    protected void handleAlertWarningMessage(short alertDescription) throws IOException {
        if (41 == alertDescription && null != this.certificateRequest && TlsUtils.isSSL(this.tlsServerContext)) {
            switch(this.connection_state) {
                case 12:
                    this.tlsServer.processClientSupplementalData((Vector)null);
                case 14:
                    this.notifyClientCertificate(Certificate.EMPTY_CHAIN);
                    this.connection_state = 15;
                    return;
            }
        }

        super.handleAlertWarningMessage(alertDescription);
    }

    protected void notifyClientCertificate(Certificate clientCertificate) throws IOException {
        if (null == this.certificateRequest) {
            throw new TlsFatalAlert((short)80);
        } else {
            TlsUtils.processClientCertificate(this.tlsServerContext, clientCertificate, this.keyExchange, this.tlsServer);
        }
    }

    protected void receive13ClientCertificate(ByteArrayInputStream buf) throws IOException {
        if (null == this.certificateRequest) {
            throw new TlsFatalAlert((short)10);
        } else {
            Certificate.ParseOptions options = (new Certificate.ParseOptions()).setMaxChainLength(this.tlsServer.getMaxCertificateChainLength());
            Certificate clientCertificate = Certificate.parse(options, this.tlsServerContext, buf, (OutputStream)null);
            assertEmpty(buf);
            this.notifyClientCertificate(clientCertificate);
        }
    }

    protected void receive13ClientCertificateVerify(ByteArrayInputStream buf) throws IOException {
        Certificate clientCertificate = this.tlsServerContext.getSecurityParametersHandshake().getPeerCertificate();
        if (null != clientCertificate && !clientCertificate.isEmpty()) {
            DigitallySigned certificateVerify = DigitallySigned.parse(this.tlsServerContext, buf);
            assertEmpty(buf);
            TlsUtils.verify13CertificateVerifyClient(this.tlsServerContext, this.certificateRequest, certificateVerify, this.handshakeHash);
        } else {
            throw new TlsFatalAlert((short)80);
        }
    }

    protected void receive13ClientFinished(ByteArrayInputStream buf) throws IOException {
        this.process13FinishedMessage(buf);
    }

    protected void receiveCertificateMessage(ByteArrayInputStream buf) throws IOException {
        if (null == this.certificateRequest) {
            throw new TlsFatalAlert((short)10);
        } else {
            Certificate.ParseOptions options = (new Certificate.ParseOptions()).setMaxChainLength(this.tlsServer.getMaxCertificateChainLength());
            Certificate clientCertificate = Certificate.parse(options, this.tlsServerContext, buf, (OutputStream)null);
            assertEmpty(buf);
            this.notifyClientCertificate(clientCertificate);
        }
    }

    protected void receiveCertificateVerifyMessage(ByteArrayInputStream buf) throws IOException {
        DigitallySigned certificateVerify = DigitallySigned.parse(this.tlsServerContext, buf);
        assertEmpty(buf);
        TlsUtils.verifyCertificateVerifyClient(this.tlsServerContext, this.certificateRequest, certificateVerify, this.handshakeHash);
        this.handshakeHash.stopTracking();
    }

    protected ClientHello receiveClientHelloMessage(ByteArrayInputStream buf) throws IOException {
        return ClientHello.parse(buf, (OutputStream)null);
    }

    protected void receiveClientKeyExchangeMessage(ByteArrayInputStream buf) throws IOException {
        this.keyExchange.processClientKeyExchange(buf);
        assertEmpty(buf);
        boolean isSSL = TlsUtils.isSSL(this.tlsServerContext);
        if (isSSL) {
            establishMasterSecret(this.tlsServerContext, this.keyExchange);
        }

        this.tlsServerContext.getSecurityParametersHandshake().sessionHash = TlsUtils.getCurrentPRFHash(this.handshakeHash);
        if (!isSSL) {
            establishMasterSecret(this.tlsServerContext, this.keyExchange);
        }

        this.recordStream.setPendingCipher(TlsUtils.initCipher(this.tlsServerContext));
        if (!this.expectCertificateVerifyMessage()) {
            this.handshakeHash.stopTracking();
        }

    }

    protected void send13EncryptedExtensionsMessage(Hashtable serverExtensions) throws IOException {
        byte[] extBytes = writeExtensionsData(serverExtensions);
        HandshakeMessageOutput message = new HandshakeMessageOutput((short)8);
        TlsUtils.writeOpaque16(extBytes, message);
        message.send(this);
    }

    protected void send13ServerHelloCoda(ServerHello serverHello, boolean afterHelloRetryRequest) throws IOException {
        SecurityParameters securityParameters = this.tlsServerContext.getSecurityParametersHandshake();
        byte[] serverHelloTranscriptHash = TlsUtils.getCurrentPRFHash(this.handshakeHash);
        TlsUtils.establish13PhaseHandshake(this.tlsServerContext, serverHelloTranscriptHash, this.recordStream);
        this.recordStream.enablePendingCipherWrite();
        this.recordStream.enablePendingCipherRead(true);
        this.send13EncryptedExtensionsMessage(this.serverExtensions);
        this.connection_state = 5;
        if (!this.selectedPSK13) {
            this.certificateRequest = this.tlsServer.getCertificateRequest();
            if (null != this.certificateRequest) {
                if (!this.certificateRequest.hasCertificateRequestContext(TlsUtils.EMPTY_BYTES)) {
                    throw new TlsFatalAlert((short)80);
                }

                TlsUtils.establishServerSigAlgs(securityParameters, this.certificateRequest);
                this.sendCertificateRequestMessage(this.certificateRequest);
                this.connection_state = 11;
            }

            TlsCredentialedSigner serverCredentials = TlsUtils.establish13ServerCredentials(this.tlsServer);
            if (null == serverCredentials) {
                throw new TlsFatalAlert((short)80);
            }

            Certificate serverCertificate = serverCredentials.getCertificate();
            this.send13CertificateMessage(serverCertificate);
            securityParameters.tlsServerEndPoint = null;
            this.connection_state = 7;
            DigitallySigned certificateVerify = TlsUtils.generate13CertificateVerify(this.tlsServerContext, serverCredentials, this.handshakeHash);
            this.send13CertificateVerifyMessage(certificateVerify);
            this.connection_state = 17;
        }

        this.send13FinishedMessage();
        this.connection_state = 20;
        byte[] serverFinishedTranscriptHash = TlsUtils.getCurrentPRFHash(this.handshakeHash);
        TlsUtils.establish13PhaseApplication(this.tlsServerContext, serverFinishedTranscriptHash, this.recordStream);
        this.recordStream.enablePendingCipherWrite();
    }

    protected void sendCertificateRequestMessage(CertificateRequest certificateRequest) throws IOException {
        HandshakeMessageOutput message = new HandshakeMessageOutput((short)13);
        certificateRequest.encode(this.tlsServerContext, message);
        message.send(this);
    }

    protected void sendCertificateStatusMessage(CertificateStatus certificateStatus) throws IOException {
        HandshakeMessageOutput message = new HandshakeMessageOutput((short)22);
        certificateStatus.encode(message);
        message.send(this);
    }

    protected void sendHelloRequestMessage() throws IOException {
        HandshakeMessageOutput.send(this, (short)0, TlsUtils.EMPTY_BYTES);
    }

    protected void sendNewSessionTicketMessage(NewSessionTicket newSessionTicket) throws IOException {
        if (newSessionTicket == null) {
            throw new TlsFatalAlert((short)80);
        } else {
            HandshakeMessageOutput message = new HandshakeMessageOutput((short)4);
            newSessionTicket.encode(message);
            message.send(this);
        }
    }

    protected void sendServerHelloDoneMessage() throws IOException {
        HandshakeMessageOutput.send(this, (short)14, TlsUtils.EMPTY_BYTES);
    }

    protected void sendServerHelloMessage(ServerHello serverHello) throws IOException {
        HandshakeMessageOutput message = new HandshakeMessageOutput((short)2);
        serverHello.encode(this.tlsServerContext, message);
        message.send(this);
    }

    protected void sendServerKeyExchangeMessage(byte[] serverKeyExchange) throws IOException {
        HandshakeMessageOutput.send(this, (short)12, serverKeyExchange);
    }

    protected void skip13ClientCertificate() throws IOException {
        if (null != this.certificateRequest) {
            throw new TlsFatalAlert((short)10);
        }
    }

    protected void skip13ClientCertificateVerify() throws IOException {
        if (this.expectCertificateVerifyMessage()) {
            throw new TlsFatalAlert((short)10);
        }
    }
}
