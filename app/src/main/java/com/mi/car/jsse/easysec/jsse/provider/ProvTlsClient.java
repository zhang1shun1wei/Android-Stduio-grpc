package com.mi.car.jsse.easysec.jsse.provider;

import com.mi.car.jsse.easysec.asn1.x500.X500Name;
import com.mi.car.jsse.easysec.asn1.x509.Extensions;
import com.mi.car.jsse.easysec.jsse.BCSNIHostName;
import com.mi.car.jsse.easysec.jsse.BCSNIServerName;
import com.mi.car.jsse.easysec.jsse.BCX509Key;
import com.mi.car.jsse.easysec.tls.CertificateRequest;
import com.mi.car.jsse.easysec.tls.CertificateStatusRequest;
import com.mi.car.jsse.easysec.tls.CertificateStatusRequestItemV2;
import com.mi.car.jsse.easysec.tls.DefaultTlsClient;
import com.mi.car.jsse.easysec.tls.OCSPStatusRequest;
import com.mi.car.jsse.easysec.tls.ProtocolName;
import com.mi.car.jsse.easysec.tls.ProtocolVersion;
import com.mi.car.jsse.easysec.tls.SecurityParameters;
import com.mi.car.jsse.easysec.tls.ServerName;
import com.mi.car.jsse.easysec.tls.SessionParameters;
import com.mi.car.jsse.easysec.tls.SignatureAlgorithm;
import com.mi.car.jsse.easysec.tls.SignatureAndHashAlgorithm;
import com.mi.car.jsse.easysec.tls.TlsAuthentication;
import com.mi.car.jsse.easysec.tls.TlsCredentials;
import com.mi.car.jsse.easysec.tls.TlsDHGroupVerifier;
import com.mi.car.jsse.easysec.tls.TlsExtensionsUtils;
import com.mi.car.jsse.easysec.tls.TlsFatalAlert;
import com.mi.car.jsse.easysec.tls.TlsServerCertificate;
import com.mi.car.jsse.easysec.tls.TlsSession;
import com.mi.car.jsse.easysec.tls.TlsUtils;
import com.mi.car.jsse.easysec.tls.TrustedAuthority;
import com.mi.car.jsse.easysec.tls.crypto.impl.jcajce.JcaTlsCrypto;
import com.mi.car.jsse.easysec.util.Arrays;
import com.mi.car.jsse.easysec.util.IPAddress;
import com.mi.car.jsse.easysec.util.encoders.Hex;
import java.io.IOException;
import java.security.Principal;
import java.security.cert.X509Certificate;
import java.util.Collections;
import java.util.Hashtable;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Vector;
import java.util.logging.Level;
import java.util.logging.Logger;

class ProvTlsClient extends DefaultTlsClient implements ProvTlsPeer {
    private static final Logger LOG = Logger.getLogger(ProvTlsClient.class.getName());
    private static final boolean provClientEnableCA = PropertyUtils.getBooleanSystemProperty("jdk.tls.client.enableCAExtension", false);
    private static final boolean provClientEnableSessionResumption = PropertyUtils.getBooleanSystemProperty("com.mi.car.jsse.easysec.jsse.client.enableSessionResumption", true);
    private static final boolean provClientEnableStatusRequest = PropertyUtils.getBooleanSystemProperty("jdk.tls.client.enableStatusRequestExtension", true);
    private static final boolean provClientEnableTrustedCAKeys = PropertyUtils.getBooleanSystemProperty("com.mi.car.jsse.easysec.jsse.client.enableTrustedCAKeysExtension", false);
    private static final boolean provEnableSNIExtension = PropertyUtils.getBooleanSystemProperty("jsse.enableSNIExtension", true);
    protected final ProvTlsManager manager;
    protected final ProvSSLParameters sslParameters;
    protected final JsseSecurityParameters jsseSecurityParameters = new JsseSecurityParameters();
    protected ProvSSLSession sslSession = null;
    protected boolean handshakeComplete = false;

    ProvTlsClient(ProvTlsManager manager, ProvSSLParameters sslParameters) {
        super(manager.getContextData().getCrypto());
        this.manager = manager;
        this.sslParameters = sslParameters.copyForConnection();
    }

    protected Vector<X500Name> getCertificateAuthorities() {
        return provClientEnableCA ? JsseUtils.getCertificateAuthorities(this.manager.getContextData().getX509TrustManager()) : null;
    }

    protected CertificateStatusRequest getCertificateStatusRequest() {
        if (!provClientEnableStatusRequest) {
            return null;
        } else {
            OCSPStatusRequest ocspStatusRequest = new OCSPStatusRequest((Vector)null, (Extensions)null);
            return new CertificateStatusRequest((short)1, ocspStatusRequest);
        }
    }

    protected Vector<CertificateStatusRequestItemV2> getMultiCertStatusRequest() {
        if (!provClientEnableStatusRequest) {
            return null;
        } else {
            OCSPStatusRequest ocspStatusRequest = new OCSPStatusRequest((Vector)null, (Extensions)null);
            Vector<CertificateStatusRequestItemV2> result = new Vector(2);
            result.add(new CertificateStatusRequestItemV2((short)2, ocspStatusRequest));
            result.add(new CertificateStatusRequestItemV2((short)1, ocspStatusRequest));
            return result;
        }
    }

    protected Vector<ProtocolName> getProtocolNames() {
        return JsseUtils.getProtocolNames(this.sslParameters.getApplicationProtocols());
    }

    protected Vector<Integer> getSupportedGroups(Vector namedGroupRolesRaw) {
        return NamedGroupInfo.getSupportedGroupsLocalClient(this.jsseSecurityParameters.namedGroups);
    }

    protected Vector<ServerName> getSNIServerNames() {
        if (provEnableSNIExtension) {
            List<BCSNIServerName> sniServerNames = this.sslParameters.getServerNames();
            if (null == sniServerNames) {
                String peerHostSNI = this.manager.getPeerHostSNI();
                if (null != peerHostSNI && peerHostSNI.indexOf(46) > 0 && !IPAddress.isValid(peerHostSNI)) {
                    try {
                        sniServerNames = Collections.singletonList(new BCSNIHostName(peerHostSNI));
                    } catch (RuntimeException var5) {
                        LOG.fine("Failed to add peer host as default SNI host_name: " + peerHostSNI);
                    }
                }
            }

            if (null != sniServerNames && !sniServerNames.isEmpty()) {
                Vector<ServerName> serverNames = new Vector(sniServerNames.size());
                Iterator var3 = sniServerNames.iterator();

                while(var3.hasNext()) {
                    BCSNIServerName sniServerName = (BCSNIServerName)var3.next();
                    serverNames.add(new ServerName((short)sniServerName.getType(), sniServerName.getEncoded()));
                }

                return serverNames;
            }
        }

        return null;
    }

    public int[] getSupportedCipherSuites() {
        return this.manager.getContextData().getContext().getActiveCipherSuites(this.getCrypto(), this.sslParameters, this.getProtocolVersions());
    }

    protected Vector<SignatureAndHashAlgorithm> getSupportedSignatureAlgorithms() {
        ContextData contextData = this.manager.getContextData();
        ProtocolVersion[] activeProtocolVersions = this.getProtocolVersions();
        List<SignatureSchemeInfo> signatureSchemes = contextData.getActiveCertsSignatureSchemes(false, this.sslParameters, activeProtocolVersions, this.jsseSecurityParameters.namedGroups);
        this.jsseSecurityParameters.localSigSchemes = signatureSchemes;
        this.jsseSecurityParameters.localSigSchemesCert = signatureSchemes;
        return SignatureSchemeInfo.getSignatureAndHashAlgorithms(this.jsseSecurityParameters.localSigSchemes);
    }

    protected Vector<SignatureAndHashAlgorithm> getSupportedSignatureAlgorithmsCert() {
        return null;
    }

    public ProtocolVersion[] getSupportedVersions() {
        return this.manager.getContextData().getContext().getActiveProtocolVersions(this.sslParameters);
    }

    protected Vector<TrustedAuthority> getTrustedCAIndication() {
        if (provClientEnableTrustedCAKeys) {
            Vector<X500Name> certificateAuthorities = JsseUtils.getCertificateAuthorities(this.manager.getContextData().getX509TrustManager());
            if (null != certificateAuthorities) {
                Vector<TrustedAuthority> trustedCAKeys = new Vector(certificateAuthorities.size());
                Iterator var3 = certificateAuthorities.iterator();

                while(var3.hasNext()) {
                    X500Name certificateAuthority = (X500Name)var3.next();
                    trustedCAKeys.add(new TrustedAuthority((short)2, certificateAuthority));
                }

                return trustedCAKeys;
            }
        }

        return null;
    }

    public boolean allowLegacyResumption() {
        return JsseUtils.allowLegacyResumption();
    }

    public synchronized boolean isHandshakeComplete() {
        return this.handshakeComplete;
    }

    public TlsDHGroupVerifier getDHGroupVerifier() {
        return new ProvDHGroupVerifier();
    }

    public TlsAuthentication getAuthentication() throws IOException {
        return new TlsAuthentication() {
            public TlsCredentials getClientCredentials(CertificateRequest certificateRequest) throws IOException {
                ContextData contextData = ProvTlsClient.this.manager.getContextData();
                SecurityParameters securityParameters = ProvTlsClient.this.context.getSecurityParametersHandshake();
                ProtocolVersion negotiatedVersion = securityParameters.getNegotiatedVersion();
                boolean isTLSv13 = TlsUtils.isTLSv13(negotiatedVersion);
                Vector<SignatureAndHashAlgorithm> serverSigAlgs = securityParameters.getServerSigAlgs();
                Vector<SignatureAndHashAlgorithm> serverSigAlgsCert = securityParameters.getServerSigAlgsCert();
                ProvTlsClient.this.jsseSecurityParameters.peerSigSchemes = contextData.getSignatureSchemes(serverSigAlgs);
                ProvTlsClient.this.jsseSecurityParameters.peerSigSchemesCert = serverSigAlgs == serverSigAlgsCert ? ProvTlsClient.this.jsseSecurityParameters.peerSigSchemes : contextData.getSignatureSchemes(serverSigAlgsCert);
                if (ProvTlsClient.LOG.isLoggable(Level.FINEST)) {
                    ProvTlsClient.LOG.finest(JsseUtils.getSignatureAlgorithmsReport("Peer signature_algorithms", ProvTlsClient.this.jsseSecurityParameters.peerSigSchemes));
                    if (ProvTlsClient.this.jsseSecurityParameters.peerSigSchemesCert != ProvTlsClient.this.jsseSecurityParameters.peerSigSchemes) {
                        ProvTlsClient.LOG.finest(JsseUtils.getSignatureAlgorithmsReport("Peer signature_algorithms_cert", ProvTlsClient.this.jsseSecurityParameters.peerSigSchemesCert));
                    }
                }

                if (DummyX509KeyManager.INSTANCE == contextData.getX509KeyManager()) {
                    return null;
                } else {
                    Principal[] issuers = JsseUtils.toX500Principals(certificateRequest.getCertificateAuthorities());
                    byte[] certificateRequestContext = certificateRequest.getCertificateRequestContext();
                    if (isTLSv13 != (null != certificateRequestContext)) {
                        throw new TlsFatalAlert((short)80);
                    } else {
                        short[] certificateTypes = certificateRequest.getCertificateTypes();
                        if (isTLSv13 != (null == certificateTypes)) {
                            throw new TlsFatalAlert((short)80);
                        } else if (isTLSv13) {
                            return ProvTlsClient.this.selectClientCredentials13(issuers, certificateRequestContext);
                        } else {
                            return TlsUtils.isSignatureAlgorithmsExtensionAllowed(negotiatedVersion) ? ProvTlsClient.this.selectClientCredentials12(issuers, certificateTypes) : ProvTlsClient.this.selectClientCredentialsLegacy(issuers, certificateTypes);
                        }
                    }
                }
            }

            public void notifyServerCertificate(TlsServerCertificate serverCertificate) throws IOException {
                if (null != serverCertificate && null != serverCertificate.getCertificate() && !serverCertificate.getCertificate().isEmpty()) {
                    X509Certificate[] chain = JsseUtils.getX509CertificateChain(ProvTlsClient.this.getCrypto(), serverCertificate.getCertificate());
                    String authType = JsseUtils.getAuthTypeServer(ProvTlsClient.this.context.getSecurityParametersHandshake().getKeyExchangeAlgorithm());
                    ProvTlsClient.this.jsseSecurityParameters.statusResponses = JsseUtils.getStatusResponses(serverCertificate.getCertificateStatus());
                    ProvTlsClient.this.manager.checkServerTrusted(chain, authType);
                } else {
                    throw new TlsFatalAlert((short)40);
                }
            }
        };
    }

    public JcaTlsCrypto getCrypto() {
        return this.manager.getContextData().getCrypto();
    }

    public int getMaxCertificateChainLength() {
        return JsseUtils.getMaxCertificateChainLength();
    }

    public int getMaxHandshakeMessageSize() {
        return JsseUtils.getMaxHandshakeMessageSize();
    }

    public TlsSession getSessionToResume() {
        if (provClientEnableSessionResumption) {
            ProvSSLSession availableSSLSession = this.sslParameters.getSessionToResume();
            if (null == availableSSLSession) {
                ProvSSLSessionContext sslSessionContext = this.manager.getContextData().getClientSessionContext();
                availableSSLSession = sslSessionContext.getSessionImpl(this.manager.getPeerHost(), this.manager.getPeerPort());
            }

            if (null != availableSSLSession) {
                TlsSession sessionToResume = availableSSLSession.getTlsSession();
                SessionParameters resumableSessionParameters = this.getResumableSessionParameters(availableSSLSession, sessionToResume);
                if (null != resumableSessionParameters) {
                    this.sslSession = availableSSLSession;
                    if (!this.manager.getEnableSessionCreation()) {
                        this.cipherSuites = new int[]{resumableSessionParameters.getCipherSuite()};
                    }

                    return sessionToResume;
                }
            }
        }

        JsseUtils.checkSessionCreationEnabled(this.manager);
        return null;
    }

    public void notifyAlertRaised(short alertLevel, short alertDescription, String message, Throwable cause) {
        super.notifyAlertRaised(alertLevel, alertDescription, message, cause);
        Level level = alertLevel == 1 ? Level.FINE : (alertDescription == 80 ? Level.WARNING : Level.INFO);
        if (LOG.isLoggable(level)) {
            String msg = JsseUtils.getAlertLogMessage("Client raised", alertLevel, alertDescription);
            if (message != null) {
                msg = msg + ": " + message;
            }

            LOG.log(level, msg, cause);
        }

    }

    public void notifyAlertReceived(short alertLevel, short alertDescription) {
        super.notifyAlertReceived(alertLevel, alertDescription);
        Level level = alertLevel == 1 ? Level.FINE : Level.INFO;
        if (LOG.isLoggable(level)) {
            String msg = JsseUtils.getAlertLogMessage("Client received", alertLevel, alertDescription);
            LOG.log(level, msg);
        }

    }

    public void notifyHandshakeBeginning() throws IOException {
        super.notifyHandshakeBeginning();
        ContextData contextData = this.manager.getContextData();
        ProtocolVersion[] activeProtocolVersions = this.getProtocolVersions();
        this.jsseSecurityParameters.namedGroups = contextData.getNamedGroups(this.sslParameters, activeProtocolVersions);
    }

    public synchronized void notifyHandshakeComplete() throws IOException {
        super.notifyHandshakeComplete();
        this.handshakeComplete = true;
        TlsSession connectionTlsSession = this.context.getSession();
        if (null == this.sslSession || this.sslSession.getTlsSession() != connectionTlsSession) {
            ProvSSLSessionContext sslSessionContext = this.manager.getContextData().getClientSessionContext();
            String peerHost = this.manager.getPeerHost();
            int peerPort = this.manager.getPeerPort();
            JsseSessionParameters jsseSessionParameters = new JsseSessionParameters(this.sslParameters.getEndpointIdentificationAlgorithm(), (BCSNIServerName)null);
            boolean addToCache = provClientEnableSessionResumption && !TlsUtils.isTLSv13(this.context);
            this.sslSession = sslSessionContext.reportSession(peerHost, peerPort, connectionTlsSession, jsseSessionParameters, addToCache);
        }

        this.manager.notifyHandshakeComplete(new ProvSSLConnection(this.context, this.sslSession));
    }

    public void notifySecureRenegotiation(boolean secureRenegotiation) throws IOException {
        if (!secureRenegotiation) {
            boolean allowLegacyHelloMessages = PropertyUtils.getBooleanSystemProperty("sun.security.ssl.allowLegacyHelloMessages", true);
            if (!allowLegacyHelloMessages) {
                throw new TlsFatalAlert((short)40);
            }
        }

    }

    public void notifySelectedCipherSuite(int selectedCipherSuite) {
        String selectedCipherSuiteName = this.manager.getContextData().getContext().validateNegotiatedCipherSuite(this.sslParameters, selectedCipherSuite);
        LOG.fine("Client notified of selected cipher suite: " + selectedCipherSuiteName);
        super.notifySelectedCipherSuite(selectedCipherSuite);
    }

    public void notifyServerVersion(ProtocolVersion serverVersion) throws IOException {
        String serverVersionName = this.manager.getContextData().getContext().validateNegotiatedProtocol(this.sslParameters, serverVersion);
        LOG.fine("Client notified of selected protocol version: " + serverVersionName);
        super.notifyServerVersion(serverVersion);
    }

    public void notifySessionToResume(TlsSession session) {
        if (null == session) {
            JsseUtils.checkSessionCreationEnabled(this.manager);
        }

        super.notifySessionToResume(session);
    }

    public void notifySessionID(byte[] sessionID) {
        boolean isResumed = !TlsUtils.isNullOrEmpty(sessionID) && null != this.sslSession && Arrays.areEqual(sessionID, this.sslSession.getId());
        if (isResumed) {
            LOG.fine("Server resumed session: " + Hex.toHexString(sessionID));
        } else {
            this.sslSession = null;
            if (TlsUtils.isNullOrEmpty(sessionID)) {
                LOG.fine("Server did not specify a session ID");
            } else {
                LOG.fine("Server specified new session: " + Hex.toHexString(sessionID));
            }

            JsseUtils.checkSessionCreationEnabled(this.manager);
        }

        this.manager.notifyHandshakeSession(this.manager.getContextData().getClientSessionContext(), this.context.getSecurityParametersHandshake(), this.jsseSecurityParameters, this.sslSession);
    }

    public void processServerExtensions(Hashtable serverExtensions) throws IOException {
        super.processServerExtensions(serverExtensions);
        SecurityParameters securityParameters = this.context.getSecurityParametersHandshake();
        if (null != securityParameters.getClientServerNames()) {
            boolean sniAccepted = TlsExtensionsUtils.hasServerNameExtensionServer(serverExtensions);
            LOG.finer("Server accepted SNI?: " + sniAccepted);
        }

    }

    public boolean requiresCloseNotify() {
        return JsseUtils.requireCloseNotify();
    }

    public boolean requiresExtendedMasterSecret() {
        return !JsseUtils.allowLegacyMasterSecret();
    }

    public boolean shouldUseExtendedMasterSecret() {
        return JsseUtils.useExtendedMasterSecret();
    }

    protected String[] getKeyTypesLegacy(short[] certificateTypes) throws IOException {
        String[] keyTypes = new String[certificateTypes.length];

        for(int i = 0; i < certificateTypes.length; ++i) {
            keyTypes[i] = JsseUtils.getKeyTypeLegacyClient(certificateTypes[i]);
        }

        return keyTypes;
    }

    protected SessionParameters getResumableSessionParameters(ProvSSLSession provSSLSession, TlsSession tlsSession) {
        if (null != tlsSession && tlsSession.isResumable()) {
            SessionParameters sessionParameters = tlsSession.exportSessionParameters();
            if (null != sessionParameters && ProtocolVersion.contains(this.getProtocolVersions(), sessionParameters.getNegotiatedVersion()) && Arrays.contains(this.getCipherSuites(), sessionParameters.getCipherSuite())) {
                if (TlsUtils.isTLSv13(sessionParameters.getNegotiatedVersion())) {
                    return null;
                } else {
                    String connectionEndpointID = this.sslParameters.getEndpointIdentificationAlgorithm();
                    if (null != connectionEndpointID) {
                        JsseSessionParameters jsseSessionParameters = provSSLSession.getJsseSessionParameters();
                        String sessionEndpointID = jsseSessionParameters.getEndpointIDAlgorithm();
                        if (!connectionEndpointID.equalsIgnoreCase(sessionEndpointID)) {
                            LOG.finer("Session not resumable - endpoint ID algorithm mismatch; connection: " + connectionEndpointID + ", session: " + sessionEndpointID);
                            return null;
                        }
                    }

                    return sessionParameters;
                }
            } else {
                return null;
            }
        } else {
            return null;
        }
    }

    protected TlsCredentials selectClientCredentials12(Principal[] issuers, short[] certificateTypes) throws IOException {
        LinkedHashMap<String, SignatureSchemeInfo> keyTypeMap = new LinkedHashMap();
        Iterator var4 = this.jsseSecurityParameters.peerSigSchemes.iterator();

        String selectedKeyType;
        while(var4.hasNext()) {
            SignatureSchemeInfo signatureSchemeInfo = (SignatureSchemeInfo)var4.next();
            selectedKeyType = signatureSchemeInfo.getKeyType();
            if (!keyTypeMap.containsKey(selectedKeyType)) {
                short signatureAlgorithm = signatureSchemeInfo.getSignatureAlgorithm();
                short certificateType = SignatureAlgorithm.getClientCertificateType(signatureAlgorithm);
                if (certificateType >= 0 && Arrays.contains(certificateTypes, certificateType) && this.jsseSecurityParameters.localSigSchemes.contains(signatureSchemeInfo)) {
                    keyTypeMap.put(selectedKeyType, signatureSchemeInfo);
                }
            }
        }

        if (keyTypeMap.isEmpty()) {
            LOG.fine("Client (1.2) found no usable signature schemes");
            return null;
        } else {
            String[] keyTypes = (String[])keyTypeMap.keySet().toArray(TlsUtils.EMPTY_STRINGS);
            BCX509Key x509Key = this.manager.chooseClientKey(keyTypes, issuers);
            if (null == x509Key) {
                this.handleKeyManagerMisses(keyTypeMap, (String)null);
                LOG.fine("Client (1.2) did not select any credentials");
                return null;
            } else {
                selectedKeyType = x509Key.getKeyType();
                this.handleKeyManagerMisses(keyTypeMap, selectedKeyType);
                SignatureSchemeInfo selectedSignatureSchemeInfo = (SignatureSchemeInfo)keyTypeMap.get(selectedKeyType);
                if (null == selectedSignatureSchemeInfo) {
                    throw new TlsFatalAlert((short)80, "Key manager returned invalid key type");
                } else {
                    if (LOG.isLoggable(Level.FINE)) {
                        LOG.fine("Client (1.2) selected credentials for signature scheme '" + selectedSignatureSchemeInfo + "' (keyType '" + selectedKeyType + "'), with private key algorithm '" + JsseUtils.getPrivateKeyAlgorithm(x509Key.getPrivateKey()) + "'");
                    }

                    return JsseUtils.createCredentialedSigner(this.context, this.getCrypto(), x509Key, selectedSignatureSchemeInfo.getSignatureAndHashAlgorithm());
                }
            }
        }
    }

    protected TlsCredentials selectClientCredentials13(Principal[] issuers, byte[] certificateRequestContext) throws IOException {
        LinkedHashMap<String, SignatureSchemeInfo> keyTypeMap = new LinkedHashMap();
        Iterator var4 = this.jsseSecurityParameters.peerSigSchemes.iterator();

        String selectedKeyType;
        while(var4.hasNext()) {
            SignatureSchemeInfo signatureSchemeInfo = (SignatureSchemeInfo)var4.next();
            if (signatureSchemeInfo.isSupportedPost13() && this.jsseSecurityParameters.localSigSchemes.contains(signatureSchemeInfo)) {
                selectedKeyType = signatureSchemeInfo.getKeyType13();
                if (!keyTypeMap.containsKey(selectedKeyType)) {
                    keyTypeMap.put(selectedKeyType, signatureSchemeInfo);
                }
            }
        }

        if (keyTypeMap.isEmpty()) {
            LOG.fine("Client (1.3) found no usable signature schemes");
            return null;
        } else {
            String[] keyTypes = (String[])keyTypeMap.keySet().toArray(TlsUtils.EMPTY_STRINGS);
            BCX509Key x509Key = this.manager.chooseClientKey(keyTypes, issuers);
            if (null == x509Key) {
                this.handleKeyManagerMisses(keyTypeMap, (String)null);
                LOG.fine("Client (1.3) did not select any credentials");
                return null;
            } else {
                selectedKeyType = x509Key.getKeyType();
                this.handleKeyManagerMisses(keyTypeMap, selectedKeyType);
                SignatureSchemeInfo selectedSignatureSchemeInfo = (SignatureSchemeInfo)keyTypeMap.get(selectedKeyType);
                if (null == selectedSignatureSchemeInfo) {
                    throw new TlsFatalAlert((short)80, "Key manager returned invalid key type");
                } else {
                    if (LOG.isLoggable(Level.FINE)) {
                        LOG.fine("Client (1.3) selected credentials for signature scheme '" + selectedSignatureSchemeInfo + "' (keyType '" + selectedKeyType + "'), with private key algorithm '" + JsseUtils.getPrivateKeyAlgorithm(x509Key.getPrivateKey()) + "'");
                    }

                    return JsseUtils.createCredentialedSigner13(this.context, this.getCrypto(), x509Key, selectedSignatureSchemeInfo.getSignatureAndHashAlgorithm(), certificateRequestContext);
                }
            }
        }
    }

    protected TlsCredentials selectClientCredentialsLegacy(Principal[] issuers, short[] certificateTypes) throws IOException {
        String[] keyTypes = this.getKeyTypesLegacy(certificateTypes);
        if (keyTypes.length < 1) {
            return null;
        } else {
            BCX509Key x509Key = this.manager.chooseClientKey(keyTypes, issuers);
            return null == x509Key ? null : JsseUtils.createCredentialedSigner(this.context, this.getCrypto(), x509Key, (SignatureAndHashAlgorithm)null);
        }
    }

    private void handleKeyManagerMisses(LinkedHashMap<String, SignatureSchemeInfo> keyTypeMap, String selectedKeyType) {
        Iterator var3 = keyTypeMap.entrySet().iterator();

        while(var3.hasNext()) {
            Map.Entry<String, SignatureSchemeInfo> entry = (Map.Entry)var3.next();
            String keyType = (String)entry.getKey();
            if (keyType.equals(selectedKeyType)) {
                break;
            }

            if (LOG.isLoggable(Level.FINER)) {
                SignatureSchemeInfo signatureSchemeInfo = (SignatureSchemeInfo)entry.getValue();
                LOG.finer("Client found no credentials for signature scheme '" + signatureSchemeInfo + "' (keyType '" + keyType + "')");
            }
        }

    }
}