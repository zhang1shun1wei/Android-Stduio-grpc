package com.mi.car.jsse.easysec.tls;

import com.mi.car.jsse.easysec.tls.DTLSReliableHandshake;
import com.mi.car.jsse.easysec.tls.SessionParameters;
import com.mi.car.jsse.easysec.tls.crypto.TlsSecret;
import com.mi.car.jsse.easysec.tls.crypto.TlsStreamSigner;
import com.mi.car.jsse.easysec.util.Arrays;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.util.Enumeration;
import java.util.Hashtable;
import java.util.Vector;

public class DTLSClientProtocol extends DTLSProtocol {
    public DTLSClientProtocol() {
    }

    public DTLSTransport connect(TlsClient client, DatagramTransport transport) throws IOException {
        if (client == null) {
            throw new IllegalArgumentException("'client' cannot be null");
        } else if (transport == null) {
            throw new IllegalArgumentException("'transport' cannot be null");
        } else {
            DTLSClientProtocol.ClientHandshakeState state = new DTLSClientProtocol.ClientHandshakeState();
            state.client = client;
            state.clientContext = new TlsClientContextImpl(client.getCrypto());
            client.init(state.clientContext);
            state.clientContext.handshakeBeginning(client);
            SecurityParameters securityParameters = state.clientContext.getSecurityParametersHandshake();
            securityParameters.extendedPadding = client.shouldUseExtendedPadding();
            TlsSession sessionToResume = state.client.getSessionToResume();
            if (sessionToResume != null && sessionToResume.isResumable()) {
                SessionParameters sessionParameters = sessionToResume.exportSessionParameters();
                if (sessionParameters != null && (sessionParameters.isExtendedMasterSecret() || !state.client.requiresExtendedMasterSecret() && state.client.allowLegacyResumption())) {
                    TlsSecret masterSecret = sessionParameters.getMasterSecret();
                    synchronized(masterSecret) {
                        if (masterSecret.isAlive()) {
                            state.tlsSession = sessionToResume;
                            state.sessionParameters = sessionParameters;
                            state.sessionMasterSecret = state.clientContext.getCrypto().adoptSecret(masterSecret);
                        }
                    }
                }
            }

            DTLSRecordLayer recordLayer = new DTLSRecordLayer(state.clientContext, state.client, transport);
            client.notifyCloseHandle(recordLayer);

            DTLSTransport var22;
            try {
                var22 = this.clientHandshake(state, recordLayer);
            } catch (TlsFatalAlert var16) {
                this.abortClientHandshake(state, recordLayer, var16.getAlertDescription());
                throw var16;
            } catch (IOException var17) {
                this.abortClientHandshake(state, recordLayer, (short)80);
                throw var17;
            } catch (RuntimeException var18) {
                this.abortClientHandshake(state, recordLayer, (short)80);
                throw new TlsFatalAlert((short)80, var18);
            } finally {
                securityParameters.clear();
            }

            return var22;
        }
    }

    protected void abortClientHandshake(DTLSClientProtocol.ClientHandshakeState state, DTLSRecordLayer recordLayer, short alertDescription) {
        recordLayer.fail(alertDescription);
        this.invalidateSession(state);
    }

    protected DTLSTransport clientHandshake(DTLSClientProtocol.ClientHandshakeState state, DTLSRecordLayer recordLayer) throws IOException {
        SecurityParameters securityParameters = state.clientContext.getSecurityParametersHandshake();
        DTLSReliableHandshake handshake = new DTLSReliableHandshake(state.clientContext, recordLayer, state.client.getHandshakeTimeoutMillis(), (DTLSRequest)null);
        byte[] clientHelloBody = this.generateClientHello(state);
        recordLayer.setWriteVersion(ProtocolVersion.DTLSv10);
        handshake.sendMessage((short)1, clientHelloBody);

        DTLSReliableHandshake.Message serverMessage;
        byte[] supplementalDataBody;
        for(serverMessage = handshake.receiveMessage(); serverMessage.getType() == 3; serverMessage = handshake.receiveMessage()) {
            byte[] cookie = this.processHelloVerifyRequest(state, serverMessage.getBody());
            supplementalDataBody = patchClientHelloWithCookie(clientHelloBody, cookie);
            handshake.resetAfterHelloVerifyRequestClient();
            handshake.sendMessage((short)1, supplementalDataBody);
        }

        if (serverMessage.getType() == 2) {
            ProtocolVersion recordLayerVersion = recordLayer.getReadVersion();
            this.reportServerVersion(state, recordLayerVersion);
            recordLayer.setWriteVersion(recordLayerVersion);
            this.processServerHello(state, serverMessage.getBody());
            handshake.getHandshakeHash().notifyPRFDetermined();
            applyMaxFragmentLengthExtension(recordLayer, securityParameters.getMaxFragmentLength());
            if (state.resumedSession) {
                securityParameters.masterSecret = state.sessionMasterSecret;
                recordLayer.initPendingEpoch(TlsUtils.initCipher(state.clientContext));
                securityParameters.peerVerifyData = TlsUtils.calculateVerifyData(state.clientContext, handshake.getHandshakeHash(), true);
                this.processFinished(handshake.receiveMessageBody((short)20), securityParameters.getPeerVerifyData());
                securityParameters.localVerifyData = TlsUtils.calculateVerifyData(state.clientContext, handshake.getHandshakeHash(), false);
                handshake.sendMessage((short)20, securityParameters.getLocalVerifyData());
                handshake.finish();
                if (securityParameters.isExtendedMasterSecret()) {
                    securityParameters.tlsUnique = securityParameters.getPeerVerifyData();
                }

                securityParameters.localCertificate = state.sessionParameters.getLocalCertificate();
                securityParameters.peerCertificate = state.sessionParameters.getPeerCertificate();
                securityParameters.pskIdentity = state.sessionParameters.getPSKIdentity();
                securityParameters.srpIdentity = state.sessionParameters.getSRPIdentity();
                state.clientContext.handshakeComplete(state.client, state.tlsSession);
                recordLayer.initHeartbeat(state.heartbeat, 1 == state.heartbeatPolicy);
                return new DTLSTransport(recordLayer);
            } else {
                this.invalidateSession(state);
                state.tlsSession = TlsUtils.importSession(securityParameters.getSessionID(), (SessionParameters)null);
                serverMessage = handshake.receiveMessage();
                if (serverMessage.getType() == 23) {
                    this.processServerSupplementalData(state, serverMessage.getBody());
                    serverMessage = handshake.receiveMessage();
                } else {
                    state.client.processServerSupplementalData((Vector)null);
                }

                state.keyExchange = TlsUtils.initKeyExchangeClient(state.clientContext, state.client);
                if (serverMessage.getType() == 11) {
                    this.processServerCertificate(state, serverMessage.getBody());
                    serverMessage = handshake.receiveMessage();
                } else {
                    state.authentication = null;
                }

                if (serverMessage.getType() == 22) {
                    if (securityParameters.getStatusRequestVersion() < 1) {
                        throw new TlsFatalAlert((short)10);
                    }

                    this.processCertificateStatus(state, serverMessage.getBody());
                    serverMessage = handshake.receiveMessage();
                }

                TlsUtils.processServerCertificate(state.clientContext, state.certificateStatus, state.keyExchange, state.authentication, state.clientExtensions, state.serverExtensions);
                if (serverMessage.getType() == 12) {
                    this.processServerKeyExchange(state, serverMessage.getBody());
                    serverMessage = handshake.receiveMessage();
                } else {
                    state.keyExchange.skipServerKeyExchange();
                }

                if (serverMessage.getType() == 13) {
                    this.processCertificateRequest(state, serverMessage.getBody());
                    TlsUtils.establishServerSigAlgs(securityParameters, state.certificateRequest);
                    TlsUtils.trackHashAlgorithms(handshake.getHandshakeHash(), securityParameters.getServerSigAlgs());
                    serverMessage = handshake.receiveMessage();
                }

                if (serverMessage.getType() == 14) {
                    if (serverMessage.getBody().length != 0) {
                        throw new TlsFatalAlert((short)50);
                    } else {
                        Vector clientSupplementalData = state.client.getClientSupplementalData();
                        if (clientSupplementalData != null) {
                            supplementalDataBody = generateSupplementalData(clientSupplementalData);
                            handshake.sendMessage((short)23, supplementalDataBody);
                        }

                        if (null != state.certificateRequest) {
                            state.clientCredentials = TlsUtils.establishClientCredentials(state.authentication, state.certificateRequest);
                            Certificate clientCertificate = null;
                            if (null != state.clientCredentials) {
                                clientCertificate = state.clientCredentials.getCertificate();
                            }

                            sendCertificateMessage(state.clientContext, handshake, clientCertificate, (OutputStream)null);
                        }

                        TlsCredentialedSigner credentialedSigner = null;
                        TlsStreamSigner streamSigner = null;
                        if (null != state.clientCredentials) {
                            state.keyExchange.processClientCredentials(state.clientCredentials);
                            if (state.clientCredentials instanceof TlsCredentialedSigner) {
                                credentialedSigner = (TlsCredentialedSigner)state.clientCredentials;
                                streamSigner = credentialedSigner.getStreamSigner();
                            }
                        } else {
                            state.keyExchange.skipClientCredentials();
                        }

                        boolean forceBuffering = streamSigner != null;
                        TlsUtils.sealHandshakeHash(state.clientContext, handshake.getHandshakeHash(), forceBuffering);
                        byte[] clientKeyExchangeBody = this.generateClientKeyExchange(state);
                        handshake.sendMessage((short)16, clientKeyExchangeBody);
                        securityParameters.sessionHash = TlsUtils.getCurrentPRFHash(handshake.getHandshakeHash());
                        TlsProtocol.establishMasterSecret(state.clientContext, state.keyExchange);
                        recordLayer.initPendingEpoch(TlsUtils.initCipher(state.clientContext));
                        if (credentialedSigner != null) {
                            DigitallySigned certificateVerify = TlsUtils.generateCertificateVerifyClient(state.clientContext, credentialedSigner, streamSigner, handshake.getHandshakeHash());
                            byte[] certificateVerifyBody = this.generateCertificateVerify(state, certificateVerify);
                            handshake.sendMessage((short)15, certificateVerifyBody);
                        }

                        handshake.prepareToFinish();
                        securityParameters.localVerifyData = TlsUtils.calculateVerifyData(state.clientContext, handshake.getHandshakeHash(), false);
                        handshake.sendMessage((short)20, securityParameters.getLocalVerifyData());
                        if (state.expectSessionTicket) {
                            serverMessage = handshake.receiveMessage();
                            if (serverMessage.getType() != 4) {
                                throw new TlsFatalAlert((short)10);
                            }

                            securityParameters.sessionID = TlsUtils.EMPTY_BYTES;
                            this.invalidateSession(state);
                            state.tlsSession = TlsUtils.importSession(securityParameters.getSessionID(), (SessionParameters)null);
                            this.processNewSessionTicket(state, serverMessage.getBody());
                        }

                        securityParameters.peerVerifyData = TlsUtils.calculateVerifyData(state.clientContext, handshake.getHandshakeHash(), true);
                        this.processFinished(handshake.receiveMessageBody((short)20), securityParameters.getPeerVerifyData());
                        handshake.finish();
                        state.sessionMasterSecret = securityParameters.getMasterSecret();
                        state.sessionParameters = (new SessionParameters.Builder()).setCipherSuite(securityParameters.getCipherSuite()).setCompressionAlgorithm(securityParameters.getCompressionAlgorithm()).setExtendedMasterSecret(securityParameters.isExtendedMasterSecret()).setLocalCertificate(securityParameters.getLocalCertificate()).setMasterSecret(state.clientContext.getCrypto().adoptSecret(state.sessionMasterSecret)).setNegotiatedVersion(securityParameters.getNegotiatedVersion()).setPeerCertificate(securityParameters.getPeerCertificate()).setPSKIdentity(securityParameters.getPSKIdentity()).setSRPIdentity(securityParameters.getSRPIdentity()).setServerExtensions(state.serverExtensions).build();
                        state.tlsSession = TlsUtils.importSession(securityParameters.getSessionID(), state.sessionParameters);
                        securityParameters.tlsUnique = securityParameters.getLocalVerifyData();
                        state.clientContext.handshakeComplete(state.client, state.tlsSession);
                        recordLayer.initHeartbeat(state.heartbeat, 1 == state.heartbeatPolicy);
                        return new DTLSTransport(recordLayer);
                    }
                } else {
                    throw new TlsFatalAlert((short)10);
                }
            }
        } else {
            throw new TlsFatalAlert((short)10);
        }
    }

    protected byte[] generateCertificateVerify(DTLSClientProtocol.ClientHandshakeState state, DigitallySigned certificateVerify) throws IOException {
        ByteArrayOutputStream buf = new ByteArrayOutputStream();
        certificateVerify.encode(buf);
        return buf.toByteArray();
    }

    protected byte[] generateClientHello(DTLSClientProtocol.ClientHandshakeState state) throws IOException {
        TlsClientContextImpl context = state.clientContext;
        SecurityParameters securityParameters = context.getSecurityParametersHandshake();
        context.setClientSupportedVersions(state.client.getProtocolVersions());
        ProtocolVersion client_version = ProtocolVersion.getLatestDTLS(context.getClientSupportedVersions());
        if (!ProtocolVersion.isSupportedDTLSVersionClient(client_version)) {
            throw new TlsFatalAlert((short)80);
        } else {
            context.setClientVersion(client_version);
            byte[] session_id = TlsUtils.getSessionID(state.tlsSession);
            boolean fallback = state.client.isFallback();
            state.offeredCipherSuites = state.client.getCipherSuites();
            if (session_id.length > 0 && state.sessionParameters != null && (!Arrays.contains(state.offeredCipherSuites, state.sessionParameters.getCipherSuite()) || 0 != state.sessionParameters.getCompressionAlgorithm())) {
                session_id = TlsUtils.EMPTY_BYTES;
            }

            state.clientExtensions = TlsExtensionsUtils.ensureExtensionsInitialised(state.client.getClientExtensions());
            ProtocolVersion legacy_version = client_version;
            if (client_version.isLaterVersionOf(ProtocolVersion.DTLSv12)) {
                legacy_version = ProtocolVersion.DTLSv12;
                TlsExtensionsUtils.addSupportedVersionsExtensionClient(state.clientExtensions, context.getClientSupportedVersions());
            }

            context.setRSAPreMasterSecretVersion(legacy_version);
            securityParameters.clientServerNames = TlsExtensionsUtils.getServerNameExtensionClient(state.clientExtensions);
            if (TlsUtils.isSignatureAlgorithmsExtensionAllowed(client_version)) {
                TlsUtils.establishClientSigAlgs(securityParameters, state.clientExtensions);
            }

            securityParameters.clientSupportedGroups = TlsExtensionsUtils.getSupportedGroupsExtension(state.clientExtensions);
            state.clientAgreements = TlsUtils.addKeyShareToClientHello(state.clientContext, state.client, state.clientExtensions);
            if (TlsUtils.isExtendedMasterSecretOptionalDTLS(context.getClientSupportedVersions()) && state.client.shouldUseExtendedMasterSecret()) {
                TlsExtensionsUtils.addExtendedMasterSecretExtension(state.clientExtensions);
            } else if (!TlsUtils.isTLSv13(client_version) && state.client.requiresExtendedMasterSecret()) {
                throw new TlsFatalAlert((short)80);
            }

            boolean noRenegExt = ProtocolVersion.DTLSv12.isEqualOrLaterVersionOf(client_version) && state.client.shouldUseGMTUnixTime();
            securityParameters.clientRandom = TlsProtocol.createRandomBlock(noRenegExt, state.clientContext);
            noRenegExt = null == TlsUtils.getExtensionData(state.clientExtensions, TlsProtocol.EXT_RenegotiationInfo);
            boolean noRenegSCSV = !Arrays.contains(state.offeredCipherSuites, 255);
            if (noRenegExt && noRenegSCSV) {
                state.offeredCipherSuites = Arrays.append(state.offeredCipherSuites, 255);
            }

            if (fallback && !Arrays.contains(state.offeredCipherSuites, 22016)) {
                state.offeredCipherSuites = Arrays.append(state.offeredCipherSuites, 22016);
            }

            state.heartbeat = state.client.getHeartbeat();
            state.heartbeatPolicy = state.client.getHeartbeatPolicy();
            if (null != state.heartbeat || 1 == state.heartbeatPolicy) {
                TlsExtensionsUtils.addHeartbeatExtension(state.clientExtensions, new HeartbeatExtension(state.heartbeatPolicy));
            }

            ClientHello clientHello = new ClientHello(legacy_version, securityParameters.getClientRandom(), session_id, TlsUtils.EMPTY_BYTES, state.offeredCipherSuites, state.clientExtensions, 0);
            ByteArrayOutputStream buf = new ByteArrayOutputStream();
            clientHello.encode(state.clientContext, buf);
            return buf.toByteArray();
        }
    }

    protected byte[] generateClientKeyExchange(DTLSClientProtocol.ClientHandshakeState state) throws IOException {
        ByteArrayOutputStream buf = new ByteArrayOutputStream();
        state.keyExchange.generateClientKeyExchange(buf);
        return buf.toByteArray();
    }

    protected void invalidateSession(DTLSClientProtocol.ClientHandshakeState state) {
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

    protected void processCertificateRequest(DTLSClientProtocol.ClientHandshakeState state, byte[] body) throws IOException {
        if (null == state.authentication) {
            throw new TlsFatalAlert((short)40);
        } else {
            ByteArrayInputStream buf = new ByteArrayInputStream(body);
            CertificateRequest certificateRequest = CertificateRequest.parse(state.clientContext, buf);
            TlsProtocol.assertEmpty(buf);
            state.certificateRequest = TlsUtils.validateCertificateRequest(certificateRequest, state.keyExchange);
        }
    }

    protected void processCertificateStatus(DTLSClientProtocol.ClientHandshakeState state, byte[] body) throws IOException {
        ByteArrayInputStream buf = new ByteArrayInputStream(body);
        state.certificateStatus = CertificateStatus.parse(state.clientContext, buf);
        TlsProtocol.assertEmpty(buf);
    }

    protected byte[] processHelloVerifyRequest(DTLSClientProtocol.ClientHandshakeState state, byte[] body) throws IOException {
        ByteArrayInputStream buf = new ByteArrayInputStream(body);
        ProtocolVersion server_version = TlsUtils.readVersion(buf);
        int maxCookieLength = ProtocolVersion.DTLSv12.isEqualOrEarlierVersionOf(server_version) ? 255 : 32;
        byte[] cookie = TlsUtils.readOpaque8(buf, 0, maxCookieLength);
        TlsProtocol.assertEmpty(buf);
        if (!server_version.isEqualOrEarlierVersionOf(state.clientContext.getClientVersion())) {
            throw new TlsFatalAlert((short)47);
        } else {
            return cookie;
        }
    }

    protected void processNewSessionTicket(DTLSClientProtocol.ClientHandshakeState state, byte[] body) throws IOException {
        ByteArrayInputStream buf = new ByteArrayInputStream(body);
        NewSessionTicket newSessionTicket = NewSessionTicket.parse(buf);
        TlsProtocol.assertEmpty(buf);
        state.client.notifyNewSessionTicket(newSessionTicket);
    }

    protected void processServerCertificate(DTLSClientProtocol.ClientHandshakeState state, byte[] body) throws IOException {
        state.authentication = TlsUtils.receiveServerCertificate(state.clientContext, state.client, new ByteArrayInputStream(body));
    }

    protected void processServerHello(DTLSClientProtocol.ClientHandshakeState state, byte[] body) throws IOException {
        ByteArrayInputStream buf = new ByteArrayInputStream(body);
        ServerHello serverHello = ServerHello.parse(buf);
        ProtocolVersion server_version = serverHello.getVersion();
        state.serverExtensions = serverHello.getExtensions();
        SecurityParameters securityParameters = state.clientContext.getSecurityParametersHandshake();
        this.reportServerVersion(state, server_version);
        securityParameters.serverRandom = serverHello.getRandom();
        if (!state.clientContext.getClientVersion().equals(server_version)) {
            TlsUtils.checkDowngradeMarker(server_version, securityParameters.getServerRandom());
        }

        byte[] renegExtData = serverHello.getSessionID();
        securityParameters.sessionID = renegExtData;
        state.client.notifySessionID(renegExtData);
        state.resumedSession = renegExtData.length > 0 && state.tlsSession != null && Arrays.areEqual(renegExtData, state.tlsSession.getSessionID());
        int cipherSuite = validateSelectedCipherSuite(serverHello.getCipherSuite(), (short)47);
        if (TlsUtils.isValidCipherSuiteSelection(state.offeredCipherSuites, cipherSuite) && TlsUtils.isValidVersionForCipherSuite(cipherSuite, securityParameters.getNegotiatedVersion())) {
            TlsUtils.negotiatedCipherSuite(securityParameters, cipherSuite);
            state.client.notifySelectedCipherSuite(cipherSuite);
            if (TlsUtils.isTLSv13(server_version)) {
                securityParameters.extendedMasterSecret = true;
            } else {
                boolean acceptedExtendedMasterSecret = TlsExtensionsUtils.hasExtendedMasterSecretExtension(state.serverExtensions);
                if (acceptedExtendedMasterSecret) {
                    if (!state.resumedSession && !state.client.shouldUseExtendedMasterSecret()) {
                        throw new TlsFatalAlert((short)40);
                    }
                } else if (state.client.requiresExtendedMasterSecret() || state.resumedSession && !state.client.allowLegacyResumption()) {
                    throw new TlsFatalAlert((short)40);
                }

                securityParameters.extendedMasterSecret = acceptedExtendedMasterSecret;
            }

            if (state.serverExtensions != null) {
                Enumeration e = state.serverExtensions.keys();

                while(e.hasMoreElements()) {
                    Integer extType = (Integer)e.nextElement();
                    if (!extType.equals(TlsProtocol.EXT_RenegotiationInfo)) {
                        if (null == TlsUtils.getExtensionData(state.clientExtensions, extType)) {
                            throw new TlsFatalAlert((short)110);
                        }

                        if (state.resumedSession) {
                        }
                    }
                }
            }

            renegExtData = TlsUtils.getExtensionData(state.serverExtensions, TlsProtocol.EXT_RenegotiationInfo);
            if (renegExtData != null) {
                securityParameters.secureRenegotiation = true;
                if (!Arrays.constantTimeAreEqual(renegExtData, TlsProtocol.createRenegotiationInfo(TlsUtils.EMPTY_BYTES))) {
                    throw new TlsFatalAlert((short)40);
                }
            }

            state.client.notifySecureRenegotiation(securityParameters.isSecureRenegotiation());
            securityParameters.applicationProtocol = TlsExtensionsUtils.getALPNExtensionServer(state.serverExtensions);
            securityParameters.applicationProtocolSet = true;
            HeartbeatExtension heartbeatExtension = TlsExtensionsUtils.getHeartbeatExtension(state.serverExtensions);
            if (null == heartbeatExtension) {
                state.heartbeat = null;
                state.heartbeatPolicy = 2;
            } else if (1 != heartbeatExtension.getMode()) {
                state.heartbeat = null;
            }

            Hashtable sessionClientExtensions = state.clientExtensions;
            Hashtable sessionServerExtensions = state.serverExtensions;
            if (state.resumedSession) {
                if (securityParameters.getCipherSuite() != state.sessionParameters.getCipherSuite() || 0 != state.sessionParameters.getCompressionAlgorithm() || !server_version.equals(state.sessionParameters.getNegotiatedVersion())) {
                    throw new TlsFatalAlert((short)47);
                }

                sessionClientExtensions = null;
                sessionServerExtensions = state.sessionParameters.readServerExtensions();
            }

            if (sessionServerExtensions != null && !sessionServerExtensions.isEmpty()) {
                boolean serverSentEncryptThenMAC = TlsExtensionsUtils.hasEncryptThenMACExtension(sessionServerExtensions);
                if (serverSentEncryptThenMAC && !TlsUtils.isBlockCipherSuite(securityParameters.getCipherSuite())) {
                    throw new TlsFatalAlert((short)47);
                }

                securityParameters.encryptThenMAC = serverSentEncryptThenMAC;
                securityParameters.maxFragmentLength = evaluateMaxFragmentLengthExtension(state.resumedSession, sessionClientExtensions, sessionServerExtensions, (short)47);
                securityParameters.truncatedHMac = TlsExtensionsUtils.hasTruncatedHMacExtension(sessionServerExtensions);
                if (!state.resumedSession) {
                    if (TlsUtils.hasExpectedEmptyExtensionData(sessionServerExtensions, TlsExtensionsUtils.EXT_status_request_v2, (short)47)) {
                        securityParameters.statusRequestVersion = 2;
                    } else if (TlsUtils.hasExpectedEmptyExtensionData(sessionServerExtensions, TlsExtensionsUtils.EXT_status_request, (short)47)) {
                        securityParameters.statusRequestVersion = 1;
                    }
                }

                state.expectSessionTicket = !state.resumedSession && TlsUtils.hasExpectedEmptyExtensionData(sessionServerExtensions, TlsProtocol.EXT_SessionTicket, (short)47);
            }

            if (sessionClientExtensions != null) {
                state.client.processServerExtensions(sessionServerExtensions);
            }

        } else {
            throw new TlsFatalAlert((short)47);
        }
    }

    protected void processServerKeyExchange(DTLSClientProtocol.ClientHandshakeState state, byte[] body) throws IOException {
        ByteArrayInputStream buf = new ByteArrayInputStream(body);
        state.keyExchange.processServerKeyExchange(buf);
        TlsProtocol.assertEmpty(buf);
    }

    protected void processServerSupplementalData(DTLSClientProtocol.ClientHandshakeState state, byte[] body) throws IOException {
        ByteArrayInputStream buf = new ByteArrayInputStream(body);
        Vector serverSupplementalData = TlsProtocol.readSupplementalDataMessage(buf);
        state.client.processServerSupplementalData(serverSupplementalData);
    }

    protected void reportServerVersion(DTLSClientProtocol.ClientHandshakeState state, ProtocolVersion server_version) throws IOException {
        TlsClientContextImpl context = state.clientContext;
        SecurityParameters securityParameters = context.getSecurityParametersHandshake();
        ProtocolVersion currentServerVersion = securityParameters.getNegotiatedVersion();
        if (null != currentServerVersion) {
            if (!currentServerVersion.equals(server_version)) {
                throw new TlsFatalAlert((short)47);
            }
        } else if (!ProtocolVersion.contains(context.getClientSupportedVersions(), server_version)) {
            throw new TlsFatalAlert((short)70);
        } else {
            securityParameters.negotiatedVersion = server_version;
            TlsUtils.negotiatedVersionDTLSClient(state.clientContext, state.client);
        }
    }

    protected static byte[] patchClientHelloWithCookie(byte[] clientHelloBody, byte[] cookie) throws IOException {
        int sessionIDPos = 34;
        int sessionIDLength = TlsUtils.readUint8(clientHelloBody, sessionIDPos);
        int cookieLengthPos = sessionIDPos + 1 + sessionIDLength;
        int cookiePos = cookieLengthPos + 1;
        byte[] patched = new byte[clientHelloBody.length + cookie.length];
        System.arraycopy(clientHelloBody, 0, patched, 0, cookieLengthPos);
        TlsUtils.checkUint8(cookie.length);
        TlsUtils.writeUint8(cookie.length, patched, cookieLengthPos);
        System.arraycopy(cookie, 0, patched, cookiePos, cookie.length);
        System.arraycopy(clientHelloBody, cookiePos, patched, cookiePos + cookie.length, clientHelloBody.length - cookiePos);
        return patched;
    }

    protected static class ClientHandshakeState {
        TlsClient client = null;
        TlsClientContextImpl clientContext = null;
        TlsSession tlsSession = null;
        SessionParameters sessionParameters = null;
        TlsSecret sessionMasterSecret = null;
        SessionParameters.Builder sessionParametersBuilder = null;
        int[] offeredCipherSuites = null;
        Hashtable clientExtensions = null;
        Hashtable serverExtensions = null;
        boolean resumedSession = false;
        boolean expectSessionTicket = false;
        Hashtable clientAgreements = null;
        TlsKeyExchange keyExchange = null;
        TlsAuthentication authentication = null;
        CertificateStatus certificateStatus = null;
        CertificateRequest certificateRequest = null;
        TlsCredentials clientCredentials = null;
        TlsHeartbeat heartbeat = null;
        short heartbeatPolicy = 2;

        protected ClientHandshakeState() {
        }
    }
}