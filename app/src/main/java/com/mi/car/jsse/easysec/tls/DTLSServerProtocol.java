package com.mi.car.jsse.easysec.tls;

import com.mi.car.jsse.easysec.tls.Certificate;
import com.mi.car.jsse.easysec.tls.DTLSReliableHandshake;
import com.mi.car.jsse.easysec.tls.SessionParameters;
import com.mi.car.jsse.easysec.tls.crypto.TlsSecret;
import com.mi.car.jsse.easysec.util.Arrays;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.util.Hashtable;
import java.util.Vector;

public class DTLSServerProtocol extends DTLSProtocol {
    protected boolean verifyRequests = true;

    public DTLSServerProtocol() {
    }

    public boolean getVerifyRequests() {
        return this.verifyRequests;
    }

    public void setVerifyRequests(boolean verifyRequests) {
        this.verifyRequests = verifyRequests;
    }

    public DTLSTransport accept(TlsServer server, DatagramTransport transport) throws IOException {
        return this.accept(server, transport, (DTLSRequest)null);
    }

    public DTLSTransport accept(TlsServer server, DatagramTransport transport, DTLSRequest request) throws IOException {
        if (server == null) {
            throw new IllegalArgumentException("'server' cannot be null");
        } else if (transport == null) {
            throw new IllegalArgumentException("'transport' cannot be null");
        } else {
            DTLSServerProtocol.ServerHandshakeState state = new DTLSServerProtocol.ServerHandshakeState();
            state.server = server;
            state.serverContext = new TlsServerContextImpl(server.getCrypto());
            server.init(state.serverContext);
            state.serverContext.handshakeBeginning(server);
            SecurityParameters securityParameters = state.serverContext.getSecurityParametersHandshake();
            securityParameters.extendedPadding = server.shouldUseExtendedPadding();
            DTLSRecordLayer recordLayer = new DTLSRecordLayer(state.serverContext, state.server, transport);
            server.notifyCloseHandle(recordLayer);

            DTLSTransport var7;
            try {
                var7 = this.serverHandshake(state, recordLayer, request);
            } catch (TlsFatalAlert var13) {
                this.abortServerHandshake(state, recordLayer, var13.getAlertDescription());
                throw var13;
            } catch (IOException var14) {
                this.abortServerHandshake(state, recordLayer, (short)80);
                throw var14;
            } catch (RuntimeException var15) {
                this.abortServerHandshake(state, recordLayer, (short)80);
                throw new TlsFatalAlert((short)80, var15);
            } finally {
                securityParameters.clear();
            }

            return var7;
        }
    }

    protected void abortServerHandshake(DTLSServerProtocol.ServerHandshakeState state, DTLSRecordLayer recordLayer, short alertDescription) {
        recordLayer.fail(alertDescription);
        this.invalidateSession(state);
    }

    protected DTLSTransport serverHandshake(DTLSServerProtocol.ServerHandshakeState state, DTLSRecordLayer recordLayer, DTLSRequest request) throws IOException {
        SecurityParameters securityParameters = state.serverContext.getSecurityParametersHandshake();
        DTLSReliableHandshake handshake = new DTLSReliableHandshake(state.serverContext, recordLayer, state.server.getHandshakeTimeoutMillis(), request);
        DTLSReliableHandshake.Message clientMessage = null;
        if (null == request) {
            clientMessage = handshake.receiveMessage();
            if (clientMessage.getType() != 1) {
                throw new TlsFatalAlert((short)10);
            }

            this.processClientHello(state, clientMessage.getBody());
        } else {
            this.processClientHello(state, request.getClientHello());
        }

        state.tlsSession = TlsUtils.importSession(TlsUtils.EMPTY_BYTES, (SessionParameters)null);
        state.sessionParameters = null;
        state.sessionMasterSecret = null;
        securityParameters.sessionID = state.tlsSession.getSessionID();
        state.server.notifySession(state.tlsSession);
        byte[] serverHelloBody = this.generateServerHello(state, recordLayer);
        ProtocolVersion recordLayerVersion = state.serverContext.getServerVersion();
        recordLayer.setReadVersion(recordLayerVersion);
        recordLayer.setWriteVersion(recordLayerVersion);
        handshake.sendMessage((short)2, serverHelloBody);
        handshake.getHandshakeHash().notifyPRFDetermined();
        Vector serverSupplementalData = state.server.getServerSupplementalData();
        byte[] serverKeyExchange;
        if (serverSupplementalData != null) {
            serverKeyExchange = generateSupplementalData(serverSupplementalData);
            handshake.sendMessage((short)23, serverKeyExchange);
        }

        state.keyExchange = TlsUtils.initKeyExchangeServer(state.serverContext, state.server);
        state.serverCredentials = TlsUtils.establishServerCredentials(state.server);
        Certificate serverCertificate = null;
        ByteArrayOutputStream endPointHash = new ByteArrayOutputStream();
        if (state.serverCredentials == null) {
            state.keyExchange.skipServerCredentials();
        } else {
            state.keyExchange.processServerCredentials(state.serverCredentials);
            serverCertificate = state.serverCredentials.getCertificate();
            sendCertificateMessage(state.serverContext, handshake, serverCertificate, endPointHash);
        }

        securityParameters.tlsServerEndPoint = endPointHash.toByteArray();
        if (serverCertificate == null || serverCertificate.isEmpty()) {
            securityParameters.statusRequestVersion = 0;
        }

        byte[] certificateRequestBody;
        if (securityParameters.getStatusRequestVersion() > 0) {
            CertificateStatus certificateStatus = state.server.getCertificateStatus();
            if (certificateStatus != null) {
                certificateRequestBody = this.generateCertificateStatus(state, certificateStatus);
                handshake.sendMessage((short)22, certificateRequestBody);
            }
        }

        serverKeyExchange = state.keyExchange.generateServerKeyExchange();
        if (serverKeyExchange != null) {
            handshake.sendMessage((short)12, serverKeyExchange);
        }

        if (state.serverCredentials != null) {
            state.certificateRequest = state.server.getCertificateRequest();
            if (null == state.certificateRequest) {
                if (!state.keyExchange.requiresCertificateVerify()) {
                    throw new TlsFatalAlert((short)80);
                }
            } else {
                if (TlsUtils.isTLSv12(state.serverContext) != (state.certificateRequest.getSupportedSignatureAlgorithms() != null)) {
                    throw new TlsFatalAlert((short)80);
                }

                state.certificateRequest = TlsUtils.validateCertificateRequest(state.certificateRequest, state.keyExchange);
                TlsUtils.establishServerSigAlgs(securityParameters, state.certificateRequest);
                TlsUtils.trackHashAlgorithms(handshake.getHandshakeHash(), securityParameters.getServerSigAlgs());
                certificateRequestBody = this.generateCertificateRequest(state, state.certificateRequest);
                handshake.sendMessage((short)13, certificateRequestBody);
            }
        }

        handshake.sendMessage((short)14, TlsUtils.EMPTY_BYTES);
        boolean forceBuffering = false;
        TlsUtils.sealHandshakeHash(state.serverContext, handshake.getHandshakeHash(), forceBuffering);
        clientMessage = handshake.receiveMessage();
        if (clientMessage.getType() == 23) {
            this.processClientSupplementalData(state, clientMessage.getBody());
            clientMessage = handshake.receiveMessage();
        } else {
            state.server.processClientSupplementalData((Vector)null);
        }

        if (state.certificateRequest == null) {
            state.keyExchange.skipClientCredentials();
        } else if (clientMessage.getType() == 11) {
            this.processClientCertificate(state, clientMessage.getBody());
            clientMessage = handshake.receiveMessage();
        } else {
            if (TlsUtils.isTLSv12(state.serverContext)) {
                throw new TlsFatalAlert((short)10);
            }

            this.notifyClientCertificate(state, Certificate.EMPTY_CHAIN);
        }

        if (clientMessage.getType() == 16) {
            this.processClientKeyExchange(state, clientMessage.getBody());
            securityParameters.sessionHash = TlsUtils.getCurrentPRFHash(handshake.getHandshakeHash());
            TlsProtocol.establishMasterSecret(state.serverContext, state.keyExchange);
            recordLayer.initPendingEpoch(TlsUtils.initCipher(state.serverContext));
            if (this.expectCertificateVerifyMessage(state)) {
                clientMessage = handshake.receiveMessageDelayedDigest((short)15);
                byte[] certificateVerifyBody = clientMessage.getBody();
                this.processCertificateVerify(state, certificateVerifyBody, handshake.getHandshakeHash());
                handshake.prepareToFinish();
                handshake.updateHandshakeMessagesDigest(clientMessage);
            } else {
                handshake.prepareToFinish();
            }

            securityParameters.peerVerifyData = TlsUtils.calculateVerifyData(state.serverContext, handshake.getHandshakeHash(), false);
            this.processFinished(handshake.receiveMessageBody((short)20), securityParameters.getPeerVerifyData());
            if (state.expectSessionTicket) {
                NewSessionTicket newSessionTicket = state.server.getNewSessionTicket();
                byte[] newSessionTicketBody = this.generateNewSessionTicket(state, newSessionTicket);
                handshake.sendMessage((short)4, newSessionTicketBody);
            }

            securityParameters.localVerifyData = TlsUtils.calculateVerifyData(state.serverContext, handshake.getHandshakeHash(), true);
            handshake.sendMessage((short)20, securityParameters.getLocalVerifyData());
            handshake.finish();
            state.sessionMasterSecret = securityParameters.getMasterSecret();
            state.sessionParameters = (new SessionParameters.Builder()).setCipherSuite(securityParameters.getCipherSuite()).setCompressionAlgorithm(securityParameters.getCompressionAlgorithm()).setExtendedMasterSecret(securityParameters.isExtendedMasterSecret()).setLocalCertificate(securityParameters.getLocalCertificate()).setMasterSecret(state.serverContext.getCrypto().adoptSecret(state.sessionMasterSecret)).setNegotiatedVersion(securityParameters.getNegotiatedVersion()).setPeerCertificate(securityParameters.getPeerCertificate()).setPSKIdentity(securityParameters.getPSKIdentity()).setSRPIdentity(securityParameters.getSRPIdentity()).setServerExtensions(state.serverExtensions).build();
            state.tlsSession = TlsUtils.importSession(state.tlsSession.getSessionID(), state.sessionParameters);
            securityParameters.tlsUnique = securityParameters.getPeerVerifyData();
            state.serverContext.handshakeComplete(state.server, state.tlsSession);
            recordLayer.initHeartbeat(state.heartbeat, 1 == state.heartbeatPolicy);
            return new DTLSTransport(recordLayer);
        } else {
            throw new TlsFatalAlert((short)10);
        }
    }

    protected byte[] generateCertificateRequest(DTLSServerProtocol.ServerHandshakeState state, CertificateRequest certificateRequest) throws IOException {
        ByteArrayOutputStream buf = new ByteArrayOutputStream();
        certificateRequest.encode(state.serverContext, buf);
        return buf.toByteArray();
    }

    protected byte[] generateCertificateStatus(DTLSServerProtocol.ServerHandshakeState state, CertificateStatus certificateStatus) throws IOException {
        ByteArrayOutputStream buf = new ByteArrayOutputStream();
        certificateStatus.encode(buf);
        return buf.toByteArray();
    }

    protected byte[] generateNewSessionTicket(DTLSServerProtocol.ServerHandshakeState state, NewSessionTicket newSessionTicket) throws IOException {
        ByteArrayOutputStream buf = new ByteArrayOutputStream();
        newSessionTicket.encode(buf);
        return buf.toByteArray();
    }

    protected byte[] generateServerHello(DTLSServerProtocol.ServerHandshakeState state, DTLSRecordLayer recordLayer) throws IOException {
        TlsServerContextImpl context = state.serverContext;
        SecurityParameters securityParameters = context.getSecurityParametersHandshake();
        ProtocolVersion server_version = state.server.getServerVersion();
        if (!ProtocolVersion.contains(context.getClientSupportedVersions(), server_version)) {
            throw new TlsFatalAlert((short)80);
        } else {
            securityParameters.negotiatedVersion = server_version;
            TlsUtils.negotiatedVersionDTLSServer(context);
            boolean useGMTUnixTime = ProtocolVersion.DTLSv12.isEqualOrLaterVersionOf(server_version) && state.server.shouldUseGMTUnixTime();
            securityParameters.serverRandom = TlsProtocol.createRandomBlock(useGMTUnixTime, context);
            if (!server_version.equals(ProtocolVersion.getLatestDTLS(state.server.getProtocolVersions()))) {
                TlsUtils.writeDowngradeMarker(server_version, securityParameters.getServerRandom());
            }

            int cipherSuite = validateSelectedCipherSuite(state.server.getSelectedCipherSuite(), (short)80);
            if (TlsUtils.isValidCipherSuiteSelection(state.offeredCipherSuites, cipherSuite) && TlsUtils.isValidVersionForCipherSuite(cipherSuite, securityParameters.getNegotiatedVersion())) {
                TlsUtils.negotiatedCipherSuite(securityParameters, cipherSuite);
                state.serverExtensions = TlsExtensionsUtils.ensureExtensionsInitialised(state.server.getServerExtensions());
                state.server.getServerExtensionsForConnection(state.serverExtensions);
                ProtocolVersion legacy_version = server_version;
                if (server_version.isLaterVersionOf(ProtocolVersion.DTLSv12)) {
                    legacy_version = ProtocolVersion.DTLSv12;
                    TlsExtensionsUtils.addSupportedVersionsExtensionServer(state.serverExtensions, server_version);
                }

                if (securityParameters.isSecureRenegotiation()) {
                    byte[] renegExtData = TlsUtils.getExtensionData(state.serverExtensions, TlsProtocol.EXT_RenegotiationInfo);
                    boolean noRenegExt = null == renegExtData;
                    if (noRenegExt) {
                        state.serverExtensions.put(TlsProtocol.EXT_RenegotiationInfo, TlsProtocol.createRenegotiationInfo(TlsUtils.EMPTY_BYTES));
                    }
                }

                if (TlsUtils.isTLSv13(server_version)) {
                    securityParameters.extendedMasterSecret = true;
                } else {
                    securityParameters.extendedMasterSecret = state.offeredExtendedMasterSecret && state.server.shouldUseExtendedMasterSecret();
                    if (securityParameters.isExtendedMasterSecret()) {
                        TlsExtensionsUtils.addExtendedMasterSecretExtension(state.serverExtensions);
                    } else {
                        if (state.server.requiresExtendedMasterSecret()) {
                            throw new TlsFatalAlert((short)40);
                        }

                        if (state.resumedSession && !state.server.allowLegacyResumption()) {
                            throw new TlsFatalAlert((short)80);
                        }
                    }
                }

                if (null != state.heartbeat || 1 == state.heartbeatPolicy) {
                    TlsExtensionsUtils.addHeartbeatExtension(state.serverExtensions, new HeartbeatExtension(state.heartbeatPolicy));
                }

                securityParameters.applicationProtocol = TlsExtensionsUtils.getALPNExtensionServer(state.serverExtensions);
                securityParameters.applicationProtocolSet = true;
                if (!state.serverExtensions.isEmpty()) {
                    securityParameters.encryptThenMAC = TlsExtensionsUtils.hasEncryptThenMACExtension(state.serverExtensions);
                    securityParameters.maxFragmentLength = evaluateMaxFragmentLengthExtension(state.resumedSession, state.clientExtensions, state.serverExtensions, (short)80);
                    securityParameters.truncatedHMac = TlsExtensionsUtils.hasTruncatedHMacExtension(state.serverExtensions);
                    if (!state.resumedSession) {
                        if (TlsUtils.hasExpectedEmptyExtensionData(state.serverExtensions, TlsExtensionsUtils.EXT_status_request_v2, (short)80)) {
                            securityParameters.statusRequestVersion = 2;
                        } else if (TlsUtils.hasExpectedEmptyExtensionData(state.serverExtensions, TlsExtensionsUtils.EXT_status_request, (short)80)) {
                            securityParameters.statusRequestVersion = 1;
                        }
                    }

                    state.expectSessionTicket = !state.resumedSession && TlsUtils.hasExpectedEmptyExtensionData(state.serverExtensions, TlsProtocol.EXT_SessionTicket, (short)80);
                }

                applyMaxFragmentLengthExtension(recordLayer, securityParameters.getMaxFragmentLength());
                ServerHello serverHello = new ServerHello(legacy_version, securityParameters.getServerRandom(), state.tlsSession.getSessionID(), securityParameters.getCipherSuite(), state.serverExtensions);
                ByteArrayOutputStream buf = new ByteArrayOutputStream();
                serverHello.encode(state.serverContext, buf);
                return buf.toByteArray();
            } else {
                throw new TlsFatalAlert((short)80);
            }
        }
    }

    protected void invalidateSession(DTLSServerProtocol.ServerHandshakeState state) {
        if (state.sessionMasterSecret != null) {
            state.sessionMasterSecret.destroy();
            state.sessionMasterSecret = null;
        }

        if (state.sessionParameters != null) {
            state.sessionParameters.clear();
            state.sessionParameters = null;
        }

        if (state.tlsSession != null) {
            state.tlsSession.invalidate();
            state.tlsSession = null;
        }

    }

    protected void notifyClientCertificate(DTLSServerProtocol.ServerHandshakeState state, Certificate clientCertificate) throws IOException {
        if (null == state.certificateRequest) {
            throw new TlsFatalAlert((short)80);
        } else {
            TlsUtils.processClientCertificate(state.serverContext, clientCertificate, state.keyExchange, state.server);
        }
    }

    protected void processClientCertificate(DTLSServerProtocol.ServerHandshakeState state, byte[] body) throws IOException {
        ByteArrayInputStream buf = new ByteArrayInputStream(body);
        Certificate.ParseOptions options = (new Certificate.ParseOptions()).setMaxChainLength(state.server.getMaxCertificateChainLength());
        Certificate clientCertificate = Certificate.parse(options, state.serverContext, buf, (OutputStream)null);
        TlsProtocol.assertEmpty(buf);
        this.notifyClientCertificate(state, clientCertificate);
    }

    protected void processCertificateVerify(DTLSServerProtocol.ServerHandshakeState state, byte[] body, TlsHandshakeHash handshakeHash) throws IOException {
        if (state.certificateRequest == null) {
            throw new IllegalStateException();
        } else {
            ByteArrayInputStream buf = new ByteArrayInputStream(body);
            TlsServerContextImpl context = state.serverContext;
            DigitallySigned certificateVerify = DigitallySigned.parse(context, buf);
            TlsProtocol.assertEmpty(buf);
            TlsUtils.verifyCertificateVerifyClient(context, state.certificateRequest, certificateVerify, handshakeHash);
        }
    }

    protected void processClientHello(DTLSServerProtocol.ServerHandshakeState state, byte[] body) throws IOException {
        ByteArrayInputStream buf = new ByteArrayInputStream(body);
        ClientHello clientHello = ClientHello.parse(buf, NullOutputStream.INSTANCE);
        this.processClientHello(state, clientHello);
    }

    protected void processClientHello(DTLSServerProtocol.ServerHandshakeState state, ClientHello clientHello) throws IOException {
        ProtocolVersion legacy_version = clientHello.getVersion();
        state.offeredCipherSuites = clientHello.getCipherSuites();
        state.clientExtensions = clientHello.getExtensions();
        TlsServerContextImpl context = state.serverContext;
        SecurityParameters securityParameters = context.getSecurityParametersHandshake();
        if (!legacy_version.isDTLS()) {
            throw new TlsFatalAlert((short)47);
        } else {
            context.setRSAPreMasterSecretVersion(legacy_version);
            context.setClientSupportedVersions(TlsExtensionsUtils.getSupportedVersionsExtensionClient(state.clientExtensions));
            ProtocolVersion client_version = legacy_version;
            if (null == context.getClientSupportedVersions()) {
                if (legacy_version.isLaterVersionOf(ProtocolVersion.DTLSv12)) {
                    client_version = ProtocolVersion.DTLSv12;
                }

                context.setClientSupportedVersions(client_version.downTo(ProtocolVersion.DTLSv10));
            } else {
                client_version = ProtocolVersion.getLatestDTLS(context.getClientSupportedVersions());
            }

            if (!ProtocolVersion.SERVER_EARLIEST_SUPPORTED_DTLS.isEqualOrEarlierVersionOf(client_version)) {
                throw new TlsFatalAlert((short)70);
            } else {
                context.setClientVersion(client_version);
                state.server.notifyClientVersion(context.getClientVersion());
                securityParameters.clientRandom = clientHello.getRandom();
                state.server.notifyFallback(Arrays.contains(state.offeredCipherSuites, 22016));
                state.server.notifyOfferedCipherSuites(state.offeredCipherSuites);
                if (Arrays.contains(state.offeredCipherSuites, 255)) {
                    securityParameters.secureRenegotiation = true;
                }

                byte[] renegExtData = TlsUtils.getExtensionData(state.clientExtensions, TlsProtocol.EXT_RenegotiationInfo);
                if (renegExtData != null) {
                    securityParameters.secureRenegotiation = true;
                    if (!Arrays.constantTimeAreEqual(renegExtData, TlsProtocol.createRenegotiationInfo(TlsUtils.EMPTY_BYTES))) {
                        throw new TlsFatalAlert((short)40);
                    }
                }

                state.server.notifySecureRenegotiation(securityParameters.isSecureRenegotiation());
                state.offeredExtendedMasterSecret = TlsExtensionsUtils.hasExtendedMasterSecretExtension(state.clientExtensions);
                if (state.clientExtensions != null) {
                    TlsExtensionsUtils.getPaddingExtension(state.clientExtensions);
                    securityParameters.clientServerNames = TlsExtensionsUtils.getServerNameExtensionClient(state.clientExtensions);
                    if (TlsUtils.isSignatureAlgorithmsExtensionAllowed(client_version)) {
                        TlsUtils.establishClientSigAlgs(securityParameters, state.clientExtensions);
                    }

                    securityParameters.clientSupportedGroups = TlsExtensionsUtils.getSupportedGroupsExtension(state.clientExtensions);
                    HeartbeatExtension heartbeatExtension = TlsExtensionsUtils.getHeartbeatExtension(state.clientExtensions);
                    if (null != heartbeatExtension) {
                        if (1 == heartbeatExtension.getMode()) {
                            state.heartbeat = state.server.getHeartbeat();
                        }

                        state.heartbeatPolicy = state.server.getHeartbeatPolicy();
                    }

                    state.server.processClientExtensions(state.clientExtensions);
                }

            }
        }
    }

    protected void processClientKeyExchange(DTLSServerProtocol.ServerHandshakeState state, byte[] body) throws IOException {
        ByteArrayInputStream buf = new ByteArrayInputStream(body);
        state.keyExchange.processClientKeyExchange(buf);
        TlsProtocol.assertEmpty(buf);
    }

    protected void processClientSupplementalData(DTLSServerProtocol.ServerHandshakeState state, byte[] body) throws IOException {
        ByteArrayInputStream buf = new ByteArrayInputStream(body);
        Vector clientSupplementalData = TlsProtocol.readSupplementalDataMessage(buf);
        state.server.processClientSupplementalData(clientSupplementalData);
    }

    protected boolean expectCertificateVerifyMessage(DTLSServerProtocol.ServerHandshakeState state) {
        if (null == state.certificateRequest) {
            return false;
        } else {
            Certificate clientCertificate = state.serverContext.getSecurityParametersHandshake().getPeerCertificate();
            return null != clientCertificate && !clientCertificate.isEmpty() && (null == state.keyExchange || state.keyExchange.requiresCertificateVerify());
        }
    }

    protected static class ServerHandshakeState {
        TlsServer server = null;
        TlsServerContextImpl serverContext = null;
        TlsSession tlsSession = null;
        SessionParameters sessionParameters = null;
        TlsSecret sessionMasterSecret = null;
        SessionParameters.Builder sessionParametersBuilder = null;
        int[] offeredCipherSuites = null;
        Hashtable clientExtensions = null;
        Hashtable serverExtensions = null;
        boolean offeredExtendedMasterSecret = false;
        boolean resumedSession = false;
        boolean expectSessionTicket = false;
        TlsKeyExchange keyExchange = null;
        TlsCredentials serverCredentials = null;
        CertificateRequest certificateRequest = null;
        TlsHeartbeat heartbeat = null;
        short heartbeatPolicy = 2;

        protected ServerHandshakeState() {
        }
    }
}
