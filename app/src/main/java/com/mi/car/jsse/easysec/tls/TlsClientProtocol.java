//
// Source code recreated from a .class file by IntelliJ IDEA
// (powered by FernFlower decompiler)
//

package com.mi.car.jsse.easysec.tls;

import com.mi.car.jsse.easysec.tls.OfferedPsks.BindersConfig;
import com.mi.car.jsse.easysec.tls.crypto.TlsAgreement;
import com.mi.car.jsse.easysec.tls.crypto.TlsSecret;
import com.mi.car.jsse.easysec.tls.crypto.TlsStreamSigner;
import com.mi.car.jsse.easysec.util.Arrays;
import com.mi.car.jsse.easysec.util.Integers;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.Enumeration;
import java.util.Hashtable;
import java.util.Vector;

public class TlsClientProtocol extends TlsProtocol {
    protected TlsClient tlsClient = null;
    TlsClientContextImpl tlsClientContext = null;
    protected Hashtable clientAgreements = null;
    BindersConfig clientBinders = null;
    protected ClientHello clientHello = null;
    protected TlsKeyExchange keyExchange = null;
    protected TlsAuthentication authentication = null;
    protected CertificateStatus certificateStatus = null;
    protected CertificateRequest certificateRequest = null;

    public TlsClientProtocol() {
    }

    public TlsClientProtocol(InputStream input, OutputStream output) {
        super(input, output);
    }

    public void connect(TlsClient tlsClient) throws IOException {
        if (tlsClient == null) {
            throw new IllegalArgumentException("'tlsClient' cannot be null");
        } else if (this.tlsClient != null) {
            throw new IllegalStateException("'connect' can only be called once");
        } else {
            this.tlsClient = tlsClient;
            this.tlsClientContext = new TlsClientContextImpl(tlsClient.getCrypto());
            tlsClient.init(this.tlsClientContext);
            tlsClient.notifyCloseHandle(this);
            this.beginHandshake(false);
            if (this.blocking) {
                this.blockForHandshake();
            }

        }
    }

    protected void beginHandshake(boolean renegotiation) throws IOException {
        super.beginHandshake(renegotiation);
        this.sendClientHello();
        this.connection_state = 1;
    }

    protected void cleanupHandshake() {
        super.cleanupHandshake();
        this.clientAgreements = null;
        this.clientBinders = null;
        this.clientHello = null;
        this.keyExchange = null;
        this.authentication = null;
        this.certificateStatus = null;
        this.certificateRequest = null;
    }

    protected TlsContext getContext() {
        return this.tlsClientContext;
    }

    AbstractTlsContext getContextAdmin() {
        return this.tlsClientContext;
    }

    protected TlsPeer getPeer() {
        return this.tlsClient;
    }

    protected void handle13HandshakeMessage(short type, HandshakeMessageInput buf) throws IOException {
        if (this.isTLSv13ConnectionState() && !this.resumedSession) {
            switch(type) {
                case 0:
                case 1:
                case 3:
                case 5:
                case 12:
                case 14:
                case 16:
                case 21:
                case 22:
                case 23:
                case 25:
                case 254:
                default:
                    throw new TlsFatalAlert((short)10);
                case 2:
                    switch(this.connection_state) {
                        case 1:
                            throw new TlsFatalAlert((short)80);
                        case 3:
                            ServerHello serverHello = this.receiveServerHelloMessage(buf);
                            if (serverHello.isHelloRetryRequest()) {
                                throw new TlsFatalAlert((short)10);
                            }

                            this.process13ServerHello(serverHello, true);
                            buf.updateHash(this.handshakeHash);
                            this.connection_state = 4;
                            this.process13ServerHelloCoda(serverHello, true);
                            return;
                        default:
                            throw new TlsFatalAlert((short)10);
                    }
                case 4:
                    this.receive13NewSessionTicket(buf);
                    break;
                case 8:
                    switch(this.connection_state) {
                        case 4:
                            this.receive13EncryptedExtensions(buf);
                            this.connection_state = 5;
                            return;
                        default:
                            throw new TlsFatalAlert((short)10);
                    }
                case 11:
                    switch(this.connection_state) {
                        case 5:
                            this.skip13CertificateRequest();
                        case 11:
                            this.receive13ServerCertificate(buf);
                            this.connection_state = 7;
                            return;
                        default:
                            throw new TlsFatalAlert((short)10);
                    }
                case 13:
                    switch(this.connection_state) {
                        case 5:
                            this.receive13CertificateRequest(buf, false);
                            this.connection_state = 11;
                            return;
                        case 21:
                            throw new TlsFatalAlert((short)10);
                        default:
                            throw new TlsFatalAlert((short)10);
                    }
                case 15:
                    switch(this.connection_state) {
                        case 7:
                            this.receive13ServerCertificateVerify(buf);
                            buf.updateHash(this.handshakeHash);
                            this.connection_state = 9;
                            return;
                        default:
                            throw new TlsFatalAlert((short)10);
                    }
                case 20:
                    switch(this.connection_state) {
                        case 5:
                            this.skip13CertificateRequest();
                        case 11:
                            this.skip13ServerCertificate();
                        case 9:
                            this.receive13ServerFinished(buf);
                            buf.updateHash(this.handshakeHash);
                            this.connection_state = 20;
                            byte[] serverFinishedTranscriptHash = TlsUtils.getCurrentPRFHash(this.handshakeHash);
                            this.recordStream.setIgnoreChangeCipherSpec(false);
                            if (null != this.certificateRequest) {
                                TlsCredentialedSigner clientCredentials = TlsUtils.establish13ClientCredentials(this.authentication, this.certificateRequest);
                                Certificate clientCertificate = null;
                                if (null != clientCredentials) {
                                    clientCertificate = clientCredentials.getCertificate();
                                }

                                if (null == clientCertificate) {
                                    clientCertificate = Certificate.EMPTY_CHAIN_TLS13;
                                }

                                this.send13CertificateMessage(clientCertificate);
                                this.connection_state = 15;
                                if (null != clientCredentials) {
                                    DigitallySigned certificateVerify = TlsUtils.generate13CertificateVerify(this.tlsClientContext, clientCredentials, this.handshakeHash);
                                    this.send13CertificateVerifyMessage(certificateVerify);
                                    this.connection_state = 17;
                                }
                            }

                            this.send13FinishedMessage();
                            this.connection_state = 18;
                            TlsUtils.establish13PhaseApplication(this.tlsClientContext, serverFinishedTranscriptHash, this.recordStream);
                            this.recordStream.enablePendingCipherWrite();
                            this.recordStream.enablePendingCipherRead(false);
                            this.completeHandshake();
                            return;
                        default:
                            throw new TlsFatalAlert((short)10);
                    }
                case 24:
                    this.receive13KeyUpdate(buf);
            }

        } else {
            throw new TlsFatalAlert((short)80);
        }
    }

    protected void handleHandshakeMessage(short type, HandshakeMessageInput buf) throws IOException {
        SecurityParameters securityParameters = this.tlsClientContext.getSecurityParameters();
        if (this.connection_state > 1 && TlsUtils.isTLSv13(securityParameters.getNegotiatedVersion())) {
            this.handle13HandshakeMessage(type, buf);
        } else if (!this.isLegacyConnectionState()) {
            throw new TlsFatalAlert((short)80);
        } else if (this.resumedSession) {
            if (type == 20 && this.connection_state == 4) {
                this.processFinishedMessage(buf);
                buf.updateHash(this.handshakeHash);
                this.connection_state = 20;
                this.sendChangeCipherSpec();
                this.sendFinishedMessage();
                this.connection_state = 18;
                this.completeHandshake();
            } else {
                throw new TlsFatalAlert((short)10);
            }
        } else {
            switch(type) {
                case 0:
                    assertEmpty(buf);
                    if (this.isApplicationDataReady()) {
                        this.handleRenegotiation();
                    }
                    break;
                case 1:
                case 3:
                case 5:
                case 8:
                case 15:
                case 16:
                case 21:
                case 24:
                case 25:
                case 254:
                default:
                    throw new TlsFatalAlert((short)10);
                case 2:
                    switch(this.connection_state) {
                        case 1:
                            ServerHello serverHello = this.receiveServerHelloMessage(buf);
                            if (serverHello.isHelloRetryRequest()) {
                                this.process13HelloRetryRequest(serverHello);
                                this.handshakeHash.notifyPRFDetermined();
                                TlsUtils.adjustTranscriptForRetry(this.handshakeHash);
                                buf.updateHash(this.handshakeHash);
                                this.connection_state = 2;
                                this.send13ClientHelloRetry();
                                this.handshakeHash.sealHashAlgorithms();
                                this.connection_state = 3;
                            } else {
                                this.processServerHello(serverHello);
                                this.handshakeHash.notifyPRFDetermined();
                                buf.updateHash(this.handshakeHash);
                                this.connection_state = 4;
                                if (TlsUtils.isTLSv13(securityParameters.getNegotiatedVersion())) {
                                    this.handshakeHash.sealHashAlgorithms();
                                    this.process13ServerHelloCoda(serverHello, false);
                                    return;
                                }
                            }

                            return;
                        default:
                            throw new TlsFatalAlert((short)10);
                    }
                case 4:
                    switch(this.connection_state) {
                        case 18:
                            if (!this.expectSessionTicket) {
                                throw new TlsFatalAlert((short)10);
                            }

                            securityParameters.sessionID = TlsUtils.EMPTY_BYTES;
                            this.invalidateSession();
                            this.tlsSession = TlsUtils.importSession(securityParameters.getSessionID(), (SessionParameters)null);
                            this.receiveNewSessionTicket(buf);
                            this.connection_state = 19;
                            return;
                        default:
                            throw new TlsFatalAlert((short)10);
                    }
                case 11:
                    switch(this.connection_state) {
                        case 4:
                            this.handleSupplementalData((Vector)null);
                        case 6:
                            this.authentication = TlsUtils.receiveServerCertificate(this.tlsClientContext, this.tlsClient, buf);
                            this.connection_state = 7;
                            return;
                        default:
                            throw new TlsFatalAlert((short)10);
                    }
                case 12:
                    switch(this.connection_state) {
                        case 4:
                            this.handleSupplementalData((Vector)null);
                        case 6:
                            this.authentication = null;
                        case 7:
                        case 8:
                            this.handleServerCertificate();
                            this.keyExchange.processServerKeyExchange(buf);
                            assertEmpty(buf);
                            this.connection_state = 10;
                            return;
                        case 5:
                        default:
                            throw new TlsFatalAlert((short)10);
                    }
                case 13:
                    switch(this.connection_state) {
                        case 7:
                        case 8:
                            this.handleServerCertificate();
                            this.keyExchange.skipServerKeyExchange();
                        case 10:
                            this.receiveCertificateRequest(buf);
                            TlsUtils.establishServerSigAlgs(securityParameters, this.certificateRequest);
                            TlsUtils.trackHashAlgorithms(this.handshakeHash, securityParameters.getServerSigAlgs());
                            this.connection_state = 11;
                            return;
                        case 9:
                        default:
                            throw new TlsFatalAlert((short)10);
                    }
                case 14:
                    switch(this.connection_state) {
                        case 4:
                            this.handleSupplementalData((Vector)null);
                        case 6:
                            this.authentication = null;
                        case 7:
                        case 8:
                            this.handleServerCertificate();
                            this.keyExchange.skipServerKeyExchange();
                        case 10:
                        case 11:
                            assertEmpty(buf);
                            this.connection_state = 12;
                            Vector clientSupplementalData = this.tlsClient.getClientSupplementalData();
                            if (clientSupplementalData != null) {
                                this.sendSupplementalDataMessage(clientSupplementalData);
                                this.connection_state = 14;
                            }

                            TlsCredentialedSigner credentialedSigner = null;
                            TlsStreamSigner streamSigner = null;
                            if (this.certificateRequest == null) {
                                this.keyExchange.skipClientCredentials();
                            } else {
                                Certificate clientCertificate = null;
                                TlsCredentials clientCredentials = TlsUtils.establishClientCredentials(this.authentication, this.certificateRequest);
                                if (null == clientCredentials) {
                                    this.keyExchange.skipClientCredentials();
                                } else {
                                    this.keyExchange.processClientCredentials(clientCredentials);
                                    clientCertificate = clientCredentials.getCertificate();
                                    if (clientCredentials instanceof TlsCredentialedSigner) {
                                        credentialedSigner = (TlsCredentialedSigner)clientCredentials;
                                        streamSigner = credentialedSigner.getStreamSigner();
                                    }
                                }

                                this.sendCertificateMessage(clientCertificate, (OutputStream)null);
                                this.connection_state = 15;
                            }

                            boolean forceBuffering = streamSigner != null;
                            TlsUtils.sealHandshakeHash(this.tlsClientContext, this.handshakeHash, forceBuffering);
                            this.sendClientKeyExchange();
                            this.connection_state = 16;
                            boolean isSSL = TlsUtils.isSSL(this.tlsClientContext);
                            if (isSSL) {
                                establishMasterSecret(this.tlsClientContext, this.keyExchange);
                            }

                            securityParameters.sessionHash = TlsUtils.getCurrentPRFHash(this.handshakeHash);
                            if (!isSSL) {
                                establishMasterSecret(this.tlsClientContext, this.keyExchange);
                            }

                            this.recordStream.setPendingCipher(TlsUtils.initCipher(this.tlsClientContext));
                            if (credentialedSigner != null) {
                                DigitallySigned certificateVerify = TlsUtils.generateCertificateVerifyClient(this.tlsClientContext, credentialedSigner, streamSigner, this.handshakeHash);
                                this.sendCertificateVerifyMessage(certificateVerify);
                                this.connection_state = 17;
                            }

                            this.handshakeHash.stopTracking();
                            this.sendChangeCipherSpec();
                            this.sendFinishedMessage();
                            this.connection_state = 18;
                            return;
                        case 5:
                        case 9:
                        default:
                            throw new TlsFatalAlert((short)10);
                    }
                case 20:
                    switch(this.connection_state) {
                        case 18:
                            if (this.expectSessionTicket) {
                                throw new TlsFatalAlert((short)10);
                            }
                        case 19:
                            this.processFinishedMessage(buf);
                            this.connection_state = 20;
                            this.completeHandshake();
                            return;
                        default:
                            throw new TlsFatalAlert((short)10);
                    }
                case 22:
                    switch(this.connection_state) {
                        case 7:
                            if (securityParameters.getStatusRequestVersion() < 1) {
                                throw new TlsFatalAlert((short)10);
                            }

                            this.certificateStatus = CertificateStatus.parse(this.tlsClientContext, buf);
                            assertEmpty(buf);
                            this.connection_state = 8;
                            return;
                        default:
                            throw new TlsFatalAlert((short)10);
                    }
                case 23:
                    switch(this.connection_state) {
                        case 4:
                            this.handleSupplementalData(readSupplementalDataMessage(buf));
                            break;
                        default:
                            throw new TlsFatalAlert((short)10);
                    }
            }

        }
    }

    protected void handleServerCertificate() throws IOException {
        TlsUtils.processServerCertificate(this.tlsClientContext, this.certificateStatus, this.keyExchange, this.authentication, this.clientExtensions, this.serverExtensions);
    }

    protected void handleSupplementalData(Vector serverSupplementalData) throws IOException {
        this.tlsClient.processServerSupplementalData(serverSupplementalData);
        this.connection_state = 6;
        this.keyExchange = TlsUtils.initKeyExchangeClient(this.tlsClientContext, this.tlsClient);
    }

    protected void process13HelloRetryRequest(ServerHello helloRetryRequest) throws IOException {
        ProtocolVersion legacy_record_version = ProtocolVersion.TLSv12;
        this.recordStream.setWriteVersion(legacy_record_version);
        SecurityParameters securityParameters = this.tlsClientContext.getSecurityParametersHandshake();
        if (securityParameters.isRenegotiating()) {
            throw new TlsFatalAlert((short)80);
        } else {
            ProtocolVersion legacy_version = helloRetryRequest.getVersion();
            byte[] legacy_session_id_echo = helloRetryRequest.getSessionID();
            int cipherSuite = helloRetryRequest.getCipherSuite();
            if (ProtocolVersion.TLSv12.equals(legacy_version) && Arrays.areEqual(this.clientHello.getSessionID(), legacy_session_id_echo) && TlsUtils.isValidCipherSuiteSelection(this.clientHello.getCipherSuites(), cipherSuite)) {
                Hashtable extensions = helloRetryRequest.getExtensions();
                if (null == extensions) {
                    throw new TlsFatalAlert((short)47);
                } else {
                    TlsUtils.checkExtensionData13(extensions, 6, (short)47);
                    Enumeration e = extensions.keys();

                    Integer extType;
                    do {
                        if (!e.hasMoreElements()) {
                            ProtocolVersion server_version = TlsExtensionsUtils.getSupportedVersionsExtensionServer(extensions);
                            if (null == server_version) {
                                throw new TlsFatalAlert((short)109);
                            }

                            if (ProtocolVersion.TLSv13.isEqualOrEarlierVersionOf(server_version) && ProtocolVersion.contains(this.tlsClientContext.getClientSupportedVersions(), server_version) && TlsUtils.isValidVersionForCipherSuite(cipherSuite, server_version)) {
                                if (null != this.clientBinders && !Arrays.contains(this.clientBinders.pskKeyExchangeModes, (short)1)) {
                                    this.clientBinders = null;
                                    this.tlsClient.notifySelectedPSK((TlsPSK)null);
                                }

                                int selected_group = TlsExtensionsUtils.getKeyShareHelloRetryRequest(extensions);
                                if (!TlsUtils.isValidKeyShareSelection(server_version, securityParameters.getClientSupportedGroups(), this.clientAgreements, selected_group)) {
                                    throw new TlsFatalAlert((short)47);
                                }

                                byte[] cookie = TlsExtensionsUtils.getCookieExtension(extensions);
                                securityParameters.negotiatedVersion = server_version;
                                TlsUtils.negotiatedVersionTLSClient(this.tlsClientContext, this.tlsClient);
                                this.resumedSession = false;
                                securityParameters.sessionID = TlsUtils.EMPTY_BYTES;
                                this.tlsClient.notifySessionID(TlsUtils.EMPTY_BYTES);
                                TlsUtils.negotiatedCipherSuite(securityParameters, cipherSuite);
                                this.tlsClient.notifySelectedCipherSuite(cipherSuite);
                                this.clientAgreements = null;
                                this.retryCookie = cookie;
                                this.retryGroup = selected_group;
                                return;
                            }

                            throw new TlsFatalAlert((short)47);
                        }

                        extType = (Integer)e.nextElement();
                    } while(44 == extType || null != TlsUtils.getExtensionData(this.clientExtensions, extType));

                    throw new TlsFatalAlert((short)110);
                }
            } else {
                throw new TlsFatalAlert((short)47);
            }
        }
    }

    protected void process13ServerHello(ServerHello serverHello, boolean afterHelloRetryRequest) throws IOException {
        SecurityParameters securityParameters = this.tlsClientContext.getSecurityParametersHandshake();
        ProtocolVersion legacy_version = serverHello.getVersion();
        byte[] legacy_session_id_echo = serverHello.getSessionID();
        int cipherSuite = serverHello.getCipherSuite();
        if (ProtocolVersion.TLSv12.equals(legacy_version) && Arrays.areEqual(this.clientHello.getSessionID(), legacy_session_id_echo)) {
            Hashtable extensions = serverHello.getExtensions();
            if (null == extensions) {
                throw new TlsFatalAlert((short)47);
            } else {
                TlsUtils.checkExtensionData13(extensions, 2, (short)47);
                if (afterHelloRetryRequest) {
                    ProtocolVersion server_version = TlsExtensionsUtils.getSupportedVersionsExtensionServer(extensions);
                    if (null == server_version) {
                        throw new TlsFatalAlert((short)109);
                    }

                    if (!securityParameters.getNegotiatedVersion().equals(server_version) || securityParameters.getCipherSuite() != cipherSuite) {
                        throw new TlsFatalAlert((short)47);
                    }
                } else {
                    if (!TlsUtils.isValidCipherSuiteSelection(this.clientHello.getCipherSuites(), cipherSuite) || !TlsUtils.isValidVersionForCipherSuite(cipherSuite, securityParameters.getNegotiatedVersion())) {
                        throw new TlsFatalAlert((short)47);
                    }

                    this.resumedSession = false;
                    securityParameters.sessionID = TlsUtils.EMPTY_BYTES;
                    this.tlsClient.notifySessionID(TlsUtils.EMPTY_BYTES);
                    TlsUtils.negotiatedCipherSuite(securityParameters, cipherSuite);
                    this.tlsClient.notifySelectedCipherSuite(cipherSuite);
                }

                this.clientHello = null;
                securityParameters.serverRandom = serverHello.getRandom();
                securityParameters.secureRenegotiation = false;
                securityParameters.extendedMasterSecret = true;
                securityParameters.statusRequestVersion = this.clientExtensions.containsKey(TlsExtensionsUtils.EXT_status_request) ? 1 : 0;
                TlsSecret pskEarlySecret = null;
                int selected_identity = TlsExtensionsUtils.getPreSharedKeyServerHello(extensions);
                TlsPSK selectedPSK = null;
                if (selected_identity >= 0) {
                    if (null == this.clientBinders || selected_identity >= this.clientBinders.psks.length) {
                        throw new TlsFatalAlert((short)47);
                    }

                    selectedPSK = this.clientBinders.psks[selected_identity];
                    if (selectedPSK.getPRFAlgorithm() != securityParameters.getPRFAlgorithm()) {
                        throw new TlsFatalAlert((short)47);
                    }

                    pskEarlySecret = this.clientBinders.earlySecrets[selected_identity];
                    this.selectedPSK13 = true;
                }

                this.tlsClient.notifySelectedPSK(selectedPSK);
                TlsSecret sharedSecret = null;
                KeyShareEntry keyShareEntry = TlsExtensionsUtils.getKeyShareServerHello(extensions);
                if (null == keyShareEntry) {
                    if (afterHelloRetryRequest || null == pskEarlySecret || !Arrays.contains(this.clientBinders.pskKeyExchangeModes, (short)0)) {
                        throw new TlsFatalAlert((short)47);
                    }
                } else {
                    if (null != pskEarlySecret && !Arrays.contains(this.clientBinders.pskKeyExchangeModes, (short)1)) {
                        throw new TlsFatalAlert((short)47);
                    }

                    int namedGroup = keyShareEntry.getNamedGroup();
                    TlsAgreement agreement = (TlsAgreement)this.clientAgreements.get(Integers.valueOf(namedGroup));
                    if (null == agreement) {
                        throw new TlsFatalAlert((short)47);
                    }

                    agreement.receivePeerValue(keyShareEntry.getKeyExchange());
                    sharedSecret = agreement.calculateSecret();
                }

                this.clientAgreements = null;
                this.clientBinders = null;
                TlsUtils.establish13PhaseSecrets(this.tlsClientContext, pskEarlySecret, sharedSecret);
                this.invalidateSession();
                this.tlsSession = TlsUtils.importSession(securityParameters.getSessionID(), (SessionParameters)null);
            }
        } else {
            throw new TlsFatalAlert((short)47);
        }
    }

    protected void process13ServerHelloCoda(ServerHello serverHello, boolean afterHelloRetryRequest) throws IOException {
        byte[] serverHelloTranscriptHash = TlsUtils.getCurrentPRFHash(this.handshakeHash);
        TlsUtils.establish13PhaseHandshake(this.tlsClientContext, serverHelloTranscriptHash, this.recordStream);
        if (!afterHelloRetryRequest) {
            this.recordStream.setIgnoreChangeCipherSpec(true);
            this.sendChangeCipherSpecMessage();
        }

        this.recordStream.enablePendingCipherWrite();
        this.recordStream.enablePendingCipherRead(false);
    }

    protected void processServerHello(ServerHello serverHello) throws IOException {
        Hashtable serverHelloExtensions = serverHello.getExtensions();
        ProtocolVersion legacy_version = serverHello.getVersion();
        ProtocolVersion supported_version = TlsExtensionsUtils.getSupportedVersionsExtensionServer(serverHelloExtensions);
        ProtocolVersion server_version;
        if (null == supported_version) {
            server_version = legacy_version;
        } else {
            if (!ProtocolVersion.TLSv12.equals(legacy_version) || !ProtocolVersion.TLSv13.isEqualOrEarlierVersionOf(supported_version)) {
                throw new TlsFatalAlert((short)47);
            }

            server_version = supported_version;
        }

        SecurityParameters securityParameters = this.tlsClientContext.getSecurityParametersHandshake();
        if (securityParameters.isRenegotiating()) {
            if (!server_version.equals(securityParameters.getNegotiatedVersion())) {
                throw new TlsFatalAlert((short)47);
            }
        } else {
            if (!ProtocolVersion.contains(this.tlsClientContext.getClientSupportedVersions(), server_version)) {
                throw new TlsFatalAlert((short)70);
            }

            ProtocolVersion legacy_record_version = server_version.isLaterVersionOf(ProtocolVersion.TLSv12) ? ProtocolVersion.TLSv12 : server_version;
            this.recordStream.setWriteVersion(legacy_record_version);
            securityParameters.negotiatedVersion = server_version;
        }

        TlsUtils.negotiatedVersionTLSClient(this.tlsClientContext, this.tlsClient);
        if (ProtocolVersion.TLSv13.isEqualOrEarlierVersionOf(server_version)) {
            this.process13ServerHello(serverHello, false);
        } else {
            int[] offeredCipherSuites = this.clientHello.getCipherSuites();
            this.clientHello = null;
            this.retryCookie = null;
            this.retryGroup = -1;
            securityParameters.serverRandom = serverHello.getRandom();
            if (!this.tlsClientContext.getClientVersion().equals(server_version)) {
                TlsUtils.checkDowngradeMarker(server_version, securityParameters.getServerRandom());
            }

            byte[] renegExtData = serverHello.getSessionID();
            securityParameters.sessionID = renegExtData;
            this.tlsClient.notifySessionID(renegExtData);
            this.resumedSession = renegExtData.length > 0 && this.tlsSession != null && Arrays.areEqual(renegExtData, this.tlsSession.getSessionID());
            int cipherSuite = serverHello.getCipherSuite();
            if (TlsUtils.isValidCipherSuiteSelection(offeredCipherSuites, cipherSuite) && TlsUtils.isValidVersionForCipherSuite(cipherSuite, securityParameters.getNegotiatedVersion())) {
                TlsUtils.negotiatedCipherSuite(securityParameters, cipherSuite);
                this.tlsClient.notifySelectedCipherSuite(cipherSuite);
                this.serverExtensions = serverHelloExtensions;
                if (this.serverExtensions != null) {
                    Enumeration e = this.serverExtensions.keys();

                    while(e.hasMoreElements()) {
                        Integer extType = (Integer)e.nextElement();
                        if (!extType.equals(EXT_RenegotiationInfo)) {
                            if (null == TlsUtils.getExtensionData(this.clientExtensions, extType)) {
                                throw new TlsFatalAlert((short)110);
                            }

                            if (this.resumedSession) {
                            }
                        }
                    }
                }

                renegExtData = TlsUtils.getExtensionData(this.serverExtensions, EXT_RenegotiationInfo);
                if (securityParameters.isRenegotiating()) {
                    if (!securityParameters.isSecureRenegotiation()) {
                        throw new TlsFatalAlert((short)80);
                    }

                    if (renegExtData == null) {
                        throw new TlsFatalAlert((short)40);
                    }

                    SecurityParameters saved = this.tlsClientContext.getSecurityParametersConnection();
                    byte[] reneg_conn_info = TlsUtils.concat(saved.getLocalVerifyData(), saved.getPeerVerifyData());
                    if (!Arrays.constantTimeAreEqual(renegExtData, createRenegotiationInfo(reneg_conn_info))) {
                        throw new TlsFatalAlert((short)40);
                    }
                } else if (renegExtData == null) {
                    securityParameters.secureRenegotiation = false;
                } else {
                    securityParameters.secureRenegotiation = true;
                    if (!Arrays.constantTimeAreEqual(renegExtData, createRenegotiationInfo(TlsUtils.EMPTY_BYTES))) {
                        throw new TlsFatalAlert((short)40);
                    }
                }

                this.tlsClient.notifySecureRenegotiation(securityParameters.isSecureRenegotiation());
                boolean acceptedExtendedMasterSecret = TlsExtensionsUtils.hasExtendedMasterSecretExtension(this.serverExtensions);
                if (acceptedExtendedMasterSecret) {
                    if (server_version.isSSL() || !this.resumedSession && !this.tlsClient.shouldUseExtendedMasterSecret()) {
                        throw new TlsFatalAlert((short)40);
                    }
                } else if (this.tlsClient.requiresExtendedMasterSecret() || this.resumedSession && !this.tlsClient.allowLegacyResumption()) {
                    throw new TlsFatalAlert((short)40);
                }

                securityParameters.extendedMasterSecret = acceptedExtendedMasterSecret;
                securityParameters.applicationProtocol = TlsExtensionsUtils.getALPNExtensionServer(this.serverExtensions);
                securityParameters.applicationProtocolSet = true;
                Hashtable sessionClientExtensions = this.clientExtensions;
                Hashtable sessionServerExtensions = this.serverExtensions;
                if (this.resumedSession) {
                    if (securityParameters.getCipherSuite() != this.sessionParameters.getCipherSuite() || 0 != this.sessionParameters.getCompressionAlgorithm() || !server_version.equals(this.sessionParameters.getNegotiatedVersion())) {
                        throw new TlsFatalAlert((short)47);
                    }

                    sessionClientExtensions = null;
                    sessionServerExtensions = this.sessionParameters.readServerExtensions();
                }

                if (sessionServerExtensions != null && !sessionServerExtensions.isEmpty()) {
                    boolean serverSentEncryptThenMAC = TlsExtensionsUtils.hasEncryptThenMACExtension(sessionServerExtensions);
                    if (serverSentEncryptThenMAC && !TlsUtils.isBlockCipherSuite(securityParameters.getCipherSuite())) {
                        throw new TlsFatalAlert((short)47);
                    }

                    securityParameters.encryptThenMAC = serverSentEncryptThenMAC;
                    securityParameters.maxFragmentLength = this.processMaxFragmentLengthExtension(sessionClientExtensions, sessionServerExtensions, (short)47);
                    securityParameters.truncatedHMac = TlsExtensionsUtils.hasTruncatedHMacExtension(sessionServerExtensions);
                    if (!this.resumedSession) {
                        if (TlsUtils.hasExpectedEmptyExtensionData(sessionServerExtensions, TlsExtensionsUtils.EXT_status_request_v2, (short)47)) {
                            securityParameters.statusRequestVersion = 2;
                        } else if (TlsUtils.hasExpectedEmptyExtensionData(sessionServerExtensions, TlsExtensionsUtils.EXT_status_request, (short)47)) {
                            securityParameters.statusRequestVersion = 1;
                        }

                        this.expectSessionTicket = TlsUtils.hasExpectedEmptyExtensionData(sessionServerExtensions, TlsProtocol.EXT_SessionTicket, (short)47);
                    }
                }

                if (sessionClientExtensions != null) {
                    this.tlsClient.processServerExtensions(sessionServerExtensions);
                }

                this.applyMaxFragmentLengthExtension(securityParameters.getMaxFragmentLength());
                if (this.resumedSession) {
                    securityParameters.masterSecret = this.sessionMasterSecret;
                    this.recordStream.setPendingCipher(TlsUtils.initCipher(this.tlsClientContext));
                } else {
                    this.invalidateSession();
                    this.tlsSession = TlsUtils.importSession(securityParameters.getSessionID(), (SessionParameters)null);
                }

            } else {
                throw new TlsFatalAlert((short)47);
            }
        }
    }

    protected void receive13CertificateRequest(ByteArrayInputStream buf, boolean postHandshakeAuth) throws IOException {
        if (postHandshakeAuth) {
            throw new TlsFatalAlert((short)80);
        } else if (this.selectedPSK13) {
            throw new TlsFatalAlert((short)10);
        } else {
            CertificateRequest certificateRequest = CertificateRequest.parse(this.tlsClientContext, buf);
            assertEmpty(buf);
            if (!certificateRequest.hasCertificateRequestContext(TlsUtils.EMPTY_BYTES)) {
                throw new TlsFatalAlert((short)47);
            } else {
                this.certificateRequest = certificateRequest;
                TlsUtils.establishServerSigAlgs(this.tlsClientContext.getSecurityParametersHandshake(), certificateRequest);
            }
        }
    }

    protected void receive13EncryptedExtensions(ByteArrayInputStream buf) throws IOException {
        byte[] extBytes = TlsUtils.readOpaque16(buf);
        assertEmpty(buf);
        this.serverExtensions = readExtensionsData13(8, extBytes);
        Enumeration e = this.serverExtensions.keys();

        while(e.hasMoreElements()) {
            Integer extType = (Integer)e.nextElement();
            if (null == TlsUtils.getExtensionData(this.clientExtensions, extType)) {
                throw new TlsFatalAlert((short)110);
            }
        }

        SecurityParameters securityParameters = this.tlsClientContext.getSecurityParametersHandshake();
        ProtocolVersion negotiatedVersion = securityParameters.getNegotiatedVersion();
        securityParameters.applicationProtocol = TlsExtensionsUtils.getALPNExtensionServer(this.serverExtensions);
        securityParameters.applicationProtocolSet = true;
        Hashtable sessionClientExtensions = this.clientExtensions;
        Hashtable sessionServerExtensions = this.serverExtensions;
        if (this.resumedSession) {
            if (securityParameters.getCipherSuite() != this.sessionParameters.getCipherSuite() || 0 != this.sessionParameters.getCompressionAlgorithm() || !negotiatedVersion.equals(this.sessionParameters.getNegotiatedVersion())) {
                throw new TlsFatalAlert((short)47);
            }

            sessionClientExtensions = null;
            sessionServerExtensions = this.sessionParameters.readServerExtensions();
        }

        securityParameters.maxFragmentLength = this.processMaxFragmentLengthExtension(sessionClientExtensions, sessionServerExtensions, (short)47);
        securityParameters.encryptThenMAC = false;
        securityParameters.truncatedHMac = false;
        securityParameters.statusRequestVersion = this.clientExtensions.containsKey(TlsExtensionsUtils.EXT_status_request) ? 1 : 0;
        this.expectSessionTicket = false;
        if (null != sessionClientExtensions) {
            this.tlsClient.processServerExtensions(this.serverExtensions);
        }

        this.applyMaxFragmentLengthExtension(securityParameters.getMaxFragmentLength());
    }

    protected void receive13NewSessionTicket(ByteArrayInputStream buf) throws IOException {
        if (!this.isApplicationDataReady()) {
            throw new TlsFatalAlert((short)10);
        } else {
            TlsUtils.readUint32(buf);
            TlsUtils.readUint32(buf);
            TlsUtils.readOpaque8(buf);
            TlsUtils.readOpaque16(buf);
            TlsUtils.readOpaque16(buf);
            assertEmpty(buf);
        }
    }

    protected void receive13ServerCertificate(ByteArrayInputStream buf) throws IOException {
        if (this.selectedPSK13) {
            throw new TlsFatalAlert((short)10);
        } else {
            this.authentication = TlsUtils.receive13ServerCertificate(this.tlsClientContext, this.tlsClient, buf);
            this.handleServerCertificate();
        }
    }

    protected void receive13ServerCertificateVerify(ByteArrayInputStream buf) throws IOException {
        Certificate serverCertificate = this.tlsClientContext.getSecurityParametersHandshake().getPeerCertificate();
        if (null != serverCertificate && !serverCertificate.isEmpty()) {
            DigitallySigned certificateVerify = DigitallySigned.parse(this.tlsClientContext, buf);
            assertEmpty(buf);
            TlsUtils.verify13CertificateVerifyServer(this.tlsClientContext, certificateVerify, this.handshakeHash);
        } else {
            throw new TlsFatalAlert((short)80);
        }
    }

    protected void receive13ServerFinished(ByteArrayInputStream buf) throws IOException {
        this.process13FinishedMessage(buf);
    }

    protected void receiveCertificateRequest(ByteArrayInputStream buf) throws IOException {
        if (null == this.authentication) {
            throw new TlsFatalAlert((short)40);
        } else {
            CertificateRequest certificateRequest = CertificateRequest.parse(this.tlsClientContext, buf);
            assertEmpty(buf);
            this.certificateRequest = TlsUtils.validateCertificateRequest(certificateRequest, this.keyExchange);
        }
    }

    protected void receiveNewSessionTicket(ByteArrayInputStream buf) throws IOException {
        NewSessionTicket newSessionTicket = NewSessionTicket.parse(buf);
        assertEmpty(buf);
        this.tlsClient.notifyNewSessionTicket(newSessionTicket);
    }

    protected ServerHello receiveServerHelloMessage(ByteArrayInputStream buf) throws IOException {
        return ServerHello.parse(buf);
    }

    protected void send13ClientHelloRetry() throws IOException {
        Hashtable clientHelloExtensions = this.clientHello.getExtensions();
        clientHelloExtensions.remove(TlsExtensionsUtils.EXT_cookie);
        clientHelloExtensions.remove(TlsExtensionsUtils.EXT_early_data);
        clientHelloExtensions.remove(TlsExtensionsUtils.EXT_key_share);
        clientHelloExtensions.remove(TlsExtensionsUtils.EXT_pre_shared_key);
        if (null != this.retryCookie) {
            TlsExtensionsUtils.addCookieExtension(clientHelloExtensions, this.retryCookie);
            this.retryCookie = null;
        }

        if (null != this.clientBinders) {
            this.clientBinders = TlsUtils.addPreSharedKeyToClientHelloRetry(this.tlsClientContext, this.clientBinders, clientHelloExtensions);
            if (null == this.clientBinders) {
                this.tlsClient.notifySelectedPSK((TlsPSK)null);
            }
        }

        if (this.retryGroup < 0) {
            throw new TlsFatalAlert((short)80);
        } else {
            this.clientAgreements = TlsUtils.addKeyShareToClientHelloRetry(this.tlsClientContext, clientHelloExtensions, this.retryGroup);
            this.recordStream.setIgnoreChangeCipherSpec(true);
            this.sendChangeCipherSpecMessage();
            this.sendClientHelloMessage();
        }
    }

    protected void sendCertificateVerifyMessage(DigitallySigned certificateVerify) throws IOException {
        HandshakeMessageOutput message = new HandshakeMessageOutput((short)15);
        certificateVerify.encode(message);
        message.send(this);
    }

    protected void sendClientHello() throws IOException {
        SecurityParameters securityParameters = this.tlsClientContext.getSecurityParametersHandshake();
        ProtocolVersion[] supportedVersions;
        ProtocolVersion earliestVersion;
        ProtocolVersion latestVersion;
        if (securityParameters.isRenegotiating()) {
            ProtocolVersion clientVersion = this.tlsClientContext.getClientVersion();
            supportedVersions = clientVersion.only();
            earliestVersion = clientVersion;
            latestVersion = clientVersion;
        } else {
            supportedVersions = this.tlsClient.getProtocolVersions();
            if (ProtocolVersion.contains(supportedVersions, ProtocolVersion.SSLv3)) {
                this.recordStream.setWriteVersion(ProtocolVersion.SSLv3);
            } else {
                this.recordStream.setWriteVersion(ProtocolVersion.TLSv10);
            }

            earliestVersion = ProtocolVersion.getEarliestTLS(supportedVersions);
            latestVersion = ProtocolVersion.getLatestTLS(supportedVersions);
            if (!ProtocolVersion.isSupportedTLSVersionClient(latestVersion)) {
                throw new TlsFatalAlert((short)80);
            }

            this.tlsClientContext.setClientVersion(latestVersion);
        }

        this.tlsClientContext.setClientSupportedVersions(supportedVersions);
        boolean offeringTLSv12Minus = ProtocolVersion.TLSv12.isEqualOrLaterVersionOf(earliestVersion);
        boolean offeringTLSv13Plus = ProtocolVersion.TLSv13.isEqualOrEarlierVersionOf(latestVersion);
        this.establishSession(offeringTLSv12Minus ? this.tlsClient.getSessionToResume() : null);
        this.tlsClient.notifySessionToResume(this.tlsSession);
        byte[] legacy_session_id = TlsUtils.getSessionID(this.tlsSession);
        boolean fallback = this.tlsClient.isFallback();
        int[] offeredCipherSuites = this.tlsClient.getCipherSuites();
        if (legacy_session_id.length > 0 && this.sessionParameters != null && (!Arrays.contains(offeredCipherSuites, this.sessionParameters.getCipherSuite()) || 0 != this.sessionParameters.getCompressionAlgorithm())) {
            legacy_session_id = TlsUtils.EMPTY_BYTES;
        }

        this.clientExtensions = TlsExtensionsUtils.ensureExtensionsInitialised(this.tlsClient.getClientExtensions());
        ProtocolVersion legacy_version = latestVersion;
        if (offeringTLSv13Plus) {
            legacy_version = ProtocolVersion.TLSv12;
            TlsExtensionsUtils.addSupportedVersionsExtensionClient(this.clientExtensions, supportedVersions);
            if (legacy_session_id.length < 1) {
                legacy_session_id = this.tlsClientContext.getNonceGenerator().generateNonce(32);
            }
        }

        this.tlsClientContext.setRSAPreMasterSecretVersion(legacy_version);
        securityParameters.clientServerNames = TlsExtensionsUtils.getServerNameExtensionClient(this.clientExtensions);
        if (TlsUtils.isSignatureAlgorithmsExtensionAllowed(latestVersion)) {
            TlsUtils.establishClientSigAlgs(securityParameters, this.clientExtensions);
        }

        securityParameters.clientSupportedGroups = TlsExtensionsUtils.getSupportedGroupsExtension(this.clientExtensions);
        this.clientBinders = TlsUtils.addPreSharedKeyToClientHello(this.tlsClientContext, this.tlsClient, this.clientExtensions, offeredCipherSuites);
        this.clientAgreements = TlsUtils.addKeyShareToClientHello(this.tlsClientContext, this.tlsClient, this.clientExtensions);
        if (TlsUtils.isExtendedMasterSecretOptionalTLS(supportedVersions) && (this.tlsClient.shouldUseExtendedMasterSecret() || null != this.sessionParameters && this.sessionParameters.isExtendedMasterSecret())) {
            TlsExtensionsUtils.addExtendedMasterSecretExtension(this.clientExtensions);
        } else if (!offeringTLSv13Plus && this.tlsClient.requiresExtendedMasterSecret()) {
            throw new TlsFatalAlert((short)80);
        }

        boolean noRenegExt = !offeringTLSv13Plus && this.tlsClient.shouldUseGMTUnixTime();
        securityParameters.clientRandom = createRandomBlock(noRenegExt, this.tlsClientContext);
        if (securityParameters.isRenegotiating()) {
            if (!securityParameters.isSecureRenegotiation()) {
                throw new TlsFatalAlert((short)80);
            }

            SecurityParameters saved = this.tlsClientContext.getSecurityParametersConnection();
            this.clientExtensions.put(EXT_RenegotiationInfo, createRenegotiationInfo(saved.getLocalVerifyData()));
        } else {
            noRenegExt = null == TlsUtils.getExtensionData(this.clientExtensions, EXT_RenegotiationInfo);
            boolean noRenegSCSV = !Arrays.contains(offeredCipherSuites, 255);
            if (noRenegExt && noRenegSCSV) {
                offeredCipherSuites = Arrays.append(offeredCipherSuites, 255);
            }
        }

        if (fallback && !Arrays.contains(offeredCipherSuites, 22016)) {
            offeredCipherSuites = Arrays.append(offeredCipherSuites, 22016);
        }

        int bindersSize = null == this.clientBinders ? 0 : this.clientBinders.bindersSize;
        this.clientHello = new ClientHello(legacy_version, securityParameters.getClientRandom(), legacy_session_id, (byte[])null, offeredCipherSuites, this.clientExtensions, bindersSize);
        this.sendClientHelloMessage();
    }

    protected void sendClientHelloMessage() throws IOException {
        HandshakeMessageOutput message = new HandshakeMessageOutput((short)1);
        this.clientHello.encode(this.tlsClientContext, message);
        message.prepareClientHello(this.handshakeHash, this.clientHello.getBindersSize());
        if (null != this.clientBinders) {
            OfferedPsks.encodeBinders(message, this.tlsClientContext.getCrypto(), this.handshakeHash, this.clientBinders);
        }

        message.sendClientHello(this, this.handshakeHash, this.clientHello.getBindersSize());
    }

    protected void sendClientKeyExchange() throws IOException {
        HandshakeMessageOutput message = new HandshakeMessageOutput((short)16);
        this.keyExchange.generateClientKeyExchange(message);
        message.send(this);
    }

    protected void skip13CertificateRequest() throws IOException {
        this.certificateRequest = null;
    }

    protected void skip13ServerCertificate() throws IOException {
        if (!this.selectedPSK13) {
            throw new TlsFatalAlert((short)10);
        } else {
            this.authentication = TlsUtils.skip13ServerCertificate(this.tlsClientContext);
        }
    }
}