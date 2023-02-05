package com.mi.car.jsse.easysec.jsse.provider;

import com.mi.car.jsse.easysec.asn1.x500.X500Name;
import com.mi.car.jsse.easysec.jsse.BCSNIMatcher;
import com.mi.car.jsse.easysec.jsse.BCSNIServerName;
import com.mi.car.jsse.easysec.jsse.BCX509Key;
import com.mi.car.jsse.easysec.jsse.java.security.BCAlgorithmConstraints;
import com.mi.car.jsse.easysec.tls.AlertDescription;
import com.mi.car.jsse.easysec.tls.Certificate;
import com.mi.car.jsse.easysec.tls.CertificateRequest;
import com.mi.car.jsse.easysec.tls.CertificateStatus;
import com.mi.car.jsse.easysec.tls.DefaultTlsDHGroupVerifier;
import com.mi.car.jsse.easysec.tls.DefaultTlsServer;
import com.mi.car.jsse.easysec.tls.ProtocolName;
import com.mi.car.jsse.easysec.tls.ProtocolVersion;
import com.mi.car.jsse.easysec.tls.SecurityParameters;
import com.mi.car.jsse.easysec.tls.ServerName;
import com.mi.car.jsse.easysec.tls.SessionParameters;
import com.mi.car.jsse.easysec.tls.SignatureAndHashAlgorithm;
import com.mi.car.jsse.easysec.tls.TlsCredentials;
import com.mi.car.jsse.easysec.tls.TlsDHUtils;
import com.mi.car.jsse.easysec.tls.TlsExtensionsUtils;
import com.mi.car.jsse.easysec.tls.TlsFatalAlert;
import com.mi.car.jsse.easysec.tls.TlsSession;
import com.mi.car.jsse.easysec.tls.TlsUtils;
import com.mi.car.jsse.easysec.tls.TrustedAuthority;
import com.mi.car.jsse.easysec.tls.crypto.DHGroup;
import com.mi.car.jsse.easysec.tls.crypto.impl.jcajce.JcaTlsCrypto;
import com.mi.car.jsse.easysec.util.Arrays;
import com.mi.car.jsse.easysec.util.encoders.Hex;
import java.io.IOException;
import java.math.BigInteger;
import java.security.Principal;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.HashSet;
import java.util.Hashtable;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.Vector;
import java.util.logging.Level;
import java.util.logging.Logger;

class ProvTlsServer extends DefaultTlsServer implements ProvTlsPeer {
    private static final Logger LOG = Logger.getLogger(ProvTlsServer.class.getName());
    private static final String PROPERTY_DEFAULT_DHE_PARAMETERS = "jdk.tls.server.defaultDHEParameters";
    private static final int provEphemeralDHKeySize = PropertyUtils.getIntegerSystemProperty("jdk.tls.ephemeralDHKeySize", DefaultTlsDHGroupVerifier.DEFAULT_MINIMUM_PRIME_BITS, 1024, 8192);
    private static final DHGroup[] provServerDefaultDHEParameters = getDefaultDHEParameters();
    private static final boolean provServerEnableCA = PropertyUtils.getBooleanSystemProperty("jdk.tls.server.enableCAExtension", true);
    private static final boolean provServerEnableSessionResumption = PropertyUtils.getBooleanSystemProperty("com.mi.car.jsse.easysec.jsse.server.enableSessionResumption", true);
    private static final boolean provServerEnableStatusRequest = false;
    private static final boolean provServerEnableTrustedCAKeys = PropertyUtils.getBooleanSystemProperty("com.mi.car.jsse.easysec.jsse.server.enableTrustedCAKeysExtension", false);
    protected TlsCredentials credentials = null;
    protected boolean handshakeComplete = false;
    protected final JsseSecurityParameters jsseSecurityParameters = new JsseSecurityParameters();
    protected Set<String> keyManagerMissCache = null;
    protected final ProvTlsManager manager;
    protected BCSNIServerName matchedSNIServerName = null;
    protected final ProvSSLParameters sslParameters;
    protected ProvSSLSession sslSession = null;

    private static DHGroup[] getDefaultDHEParameters() {
        String input;
        int limit;
        int modulus;
        int innerComma;
        int generator;
        int closeBrace;
        String propertyValue = PropertyUtils.getStringSecurityProperty(PROPERTY_DEFAULT_DHE_PARAMETERS);
        if (propertyValue == null || (limit = (input = JsseUtils.stripDoubleQuotes(JsseUtils.removeAllWhitespace(propertyValue))).length()) < 1) {
            return null;
        }
        ArrayList<DHGroup> result = new ArrayList<>();
        int outerComma = -1;
        do {
            int openBrace = outerComma + 1;
            if (openBrace >= limit || '{' != input.charAt(openBrace) || (innerComma = input.indexOf(44, (modulus = openBrace + 1))) <= modulus || (closeBrace = input.indexOf(125, (generator = innerComma + 1))) <= generator) {
                break;
            }
            try {
                BigInteger p = parseDHParameter(input, modulus, innerComma);
                BigInteger g = parseDHParameter(input, generator, closeBrace);
                DHGroup dhGroup = TlsDHUtils.getStandardGroupForDHParameters(p, g);
                if (dhGroup != null) {
                    result.add(dhGroup);
                } else if (!p.isProbablePrime(120)) {
                    LOG.log(Level.WARNING, "Non-prime modulus ignored in security property [jdk.tls.server.defaultDHEParameters]: " + p.toString(16));
                } else {
                    result.add(new DHGroup(p, null, g, 0));
                }
                outerComma = closeBrace + 1;
                if (outerComma >= limit) {
                    return (DHGroup[]) result.toArray(new DHGroup[result.size()]);
                }
            } catch (Exception e) {
            }
        } while (',' == input.charAt(outerComma));
        LOG.log(Level.WARNING, "Invalid syntax for security property [jdk.tls.server.defaultDHEParameters]");
        return null;
    }

    private static BigInteger parseDHParameter(String s, int beginIndex, int endIndex) {
        return new BigInteger(s.substring(beginIndex, endIndex), 16);
    }

    ProvTlsServer(ProvTlsManager manager2, ProvSSLParameters sslParameters2) {
        super(manager2.getContextData().getCrypto());
        this.manager = manager2;
        this.sslParameters = sslParameters2.copyForConnection();
    }

    /* access modifiers changed from: protected */
    @Override // com.mi.car.jsse.easysec.tls.AbstractTlsServer
    public boolean allowCertificateStatus() {
        return false;
    }

    /* access modifiers changed from: protected */
    @Override // com.mi.car.jsse.easysec.tls.AbstractTlsServer
    public boolean allowMultiCertStatus() {
        return false;
    }

    /* access modifiers changed from: protected */
    @Override // com.mi.car.jsse.easysec.tls.AbstractTlsServer
    public boolean allowTrustedCAIndication() {
        return this.jsseSecurityParameters.trustedIssuers != null;
    }

    /* access modifiers changed from: protected */
    @Override // com.mi.car.jsse.easysec.tls.AbstractTlsServer
    public int getMaximumNegotiableCurveBits() {
        return NamedGroupInfo.getMaximumBitsServerECDH(this.jsseSecurityParameters.namedGroups);
    }

    /* access modifiers changed from: protected */
    @Override // com.mi.car.jsse.easysec.tls.AbstractTlsServer
    public int getMaximumNegotiableFiniteFieldBits() {
        int maxBits = NamedGroupInfo.getMaximumBitsServerFFDHE(this.jsseSecurityParameters.namedGroups);
        if (maxBits >= provEphemeralDHKeySize) {
            return maxBits;
        }
        return 0;
    }

    /* access modifiers changed from: protected */
    @Override // com.mi.car.jsse.easysec.tls.AbstractTlsServer
    public Vector<ProtocolName> getProtocolNames() {
        return JsseUtils.getProtocolNames(this.sslParameters.getApplicationProtocols());
    }

    /* access modifiers changed from: protected */
    @Override // com.mi.car.jsse.easysec.tls.AbstractTlsPeer, com.mi.car.jsse.easysec.tls.DefaultTlsServer
    public int[] getSupportedCipherSuites() {
        return this.manager.getContextData().getContext().getActiveCipherSuites(getCrypto(), this.sslParameters, getProtocolVersions());
    }

    /* access modifiers changed from: protected */
    @Override // com.mi.car.jsse.easysec.tls.AbstractTlsPeer
    public ProtocolVersion[] getSupportedVersions() {
        return this.manager.getContextData().getContext().getActiveProtocolVersions(this.sslParameters);
    }

    /* access modifiers changed from: protected */
    @Override // com.mi.car.jsse.easysec.tls.AbstractTlsServer
    public boolean preferLocalCipherSuites() {
        return this.sslParameters.getUseCipherSuitesOrder();
    }

    /* access modifiers changed from: protected */
    @Override // com.mi.car.jsse.easysec.tls.AbstractTlsServer
    public boolean selectCipherSuite(int cipherSuite) throws IOException {
        TlsCredentials cipherSuiteCredentials = selectCredentials(this.jsseSecurityParameters.trustedIssuers, cipherSuite);
        if (cipherSuiteCredentials == null) {
            LOG.finer("Server found no credentials for cipher suite: " + ProvSSLContextSpi.getCipherSuiteName(cipherSuite));
            return false;
        }
        boolean result = super.selectCipherSuite(cipherSuite);
        if (!result) {
            return result;
        }
        this.credentials = cipherSuiteCredentials;
        return result;
    }

    /* access modifiers changed from: protected */
    @Override // com.mi.car.jsse.easysec.tls.AbstractTlsServer
    public int selectDH(int minimumFiniteFieldBits) {
        return NamedGroupInfo.selectServerFFDHE(this.jsseSecurityParameters.namedGroups, Math.max(minimumFiniteFieldBits, provEphemeralDHKeySize));
    }

    /* access modifiers changed from: protected */
    @Override // com.mi.car.jsse.easysec.tls.AbstractTlsServer
    public int selectDHDefault(int minimumFiniteFieldBits) {
        throw new UnsupportedOperationException();
    }

    /* access modifiers changed from: protected */
    @Override // com.mi.car.jsse.easysec.tls.AbstractTlsServer
    public int selectECDH(int minimumCurveBits) {
        return NamedGroupInfo.selectServerECDH(this.jsseSecurityParameters.namedGroups, minimumCurveBits);
    }

    /* access modifiers changed from: protected */
    @Override // com.mi.car.jsse.easysec.tls.AbstractTlsServer
    public int selectECDHDefault(int minimumCurveBits) {
        throw new UnsupportedOperationException();
    }

    /* access modifiers changed from: protected */
    @Override // com.mi.car.jsse.easysec.tls.AbstractTlsServer
    public ProtocolName selectProtocolName() throws IOException {
        if (this.sslParameters.getEngineAPSelector() == null && this.sslParameters.getSocketAPSelector() == null) {
            return super.selectProtocolName();
        }
        List<String> protocols = JsseUtils.getProtocolNames(this.clientProtocolNames);
        String protocol = this.manager.selectApplicationProtocol(Collections.unmodifiableList(protocols));
        if (protocol == null) {
            throw new TlsFatalAlert(AlertDescription.no_application_protocol);
        } else if (protocol.length() < 1) {
            return null;
        } else {
            if (protocols.contains(protocol)) {
                return ProtocolName.asUtf8Encoding(protocol);
            }
            throw new TlsFatalAlert(AlertDescription.no_application_protocol);
        }
    }

    /* access modifiers changed from: protected */
    @Override // com.mi.car.jsse.easysec.tls.AbstractTlsServer
    public boolean shouldSelectProtocolNameEarly() {
        return this.sslParameters.getEngineAPSelector() == null && this.sslParameters.getSocketAPSelector() == null;
    }

    @Override // com.mi.car.jsse.easysec.tls.TlsPeer, com.mi.car.jsse.easysec.tls.AbstractTlsPeer
    public boolean allowLegacyResumption() {
        return JsseUtils.allowLegacyResumption();
    }

    @Override // com.mi.car.jsse.easysec.tls.TlsPeer, com.mi.car.jsse.easysec.tls.AbstractTlsPeer
    public int getMaxCertificateChainLength() {
        return JsseUtils.getMaxCertificateChainLength();
    }

    @Override // com.mi.car.jsse.easysec.tls.TlsPeer, com.mi.car.jsse.easysec.tls.AbstractTlsPeer
    public int getMaxHandshakeMessageSize() {
        return JsseUtils.getMaxHandshakeMessageSize();
    }

    @Override // com.mi.car.jsse.easysec.jsse.provider.ProvTlsPeer
    public synchronized boolean isHandshakeComplete() {
        return this.handshakeComplete;
    }

    @Override // com.mi.car.jsse.easysec.tls.TlsServer, com.mi.car.jsse.easysec.tls.DefaultTlsServer
    public TlsCredentials getCredentials() throws IOException {
        return this.credentials;
    }

    @Override // com.mi.car.jsse.easysec.tls.AbstractTlsServer, com.mi.car.jsse.easysec.tls.TlsServer
    public CertificateRequest getCertificateRequest() throws IOException {
        if (!isClientAuthEnabled()) {
            return null;
        }
        ContextData contextData = this.manager.getContextData();
        ProtocolVersion negotiatedVersion = this.context.getServerVersion();
        List<SignatureSchemeInfo> signatureSchemes = contextData.getActiveCertsSignatureSchemes(true, this.sslParameters, new ProtocolVersion[]{negotiatedVersion}, this.jsseSecurityParameters.namedGroups);
        this.jsseSecurityParameters.localSigSchemes = signatureSchemes;
        this.jsseSecurityParameters.localSigSchemesCert = signatureSchemes;
        Vector<SignatureAndHashAlgorithm> serverSigAlgs = SignatureSchemeInfo.getSignatureAndHashAlgorithms(this.jsseSecurityParameters.localSigSchemes);
        Vector<X500Name> certificateAuthorities = null;
        if (provServerEnableCA) {
            certificateAuthorities = JsseUtils.getCertificateAuthorities(contextData.getX509TrustManager());
        }
        if (!TlsUtils.isTLSv13(negotiatedVersion)) {
            return new CertificateRequest(new short[]{64, 1, 2}, serverSigAlgs, certificateAuthorities);
        }
        byte[] certificateRequestContext = TlsUtils.EMPTY_BYTES;
        Vector<SignatureAndHashAlgorithm> serverSigAlgsCert = null;
        if (this.jsseSecurityParameters.localSigSchemes != this.jsseSecurityParameters.localSigSchemesCert) {
            serverSigAlgsCert = SignatureSchemeInfo.getSignatureAndHashAlgorithms(this.jsseSecurityParameters.localSigSchemesCert);
        }
        return new CertificateRequest(certificateRequestContext, serverSigAlgs, serverSigAlgsCert, certificateAuthorities);
    }

    @Override // com.mi.car.jsse.easysec.tls.AbstractTlsServer, com.mi.car.jsse.easysec.tls.TlsServer
    public CertificateStatus getCertificateStatus() throws IOException {
        return null;
    }

    @Override // com.mi.car.jsse.easysec.tls.TlsPeer, com.mi.car.jsse.easysec.tls.AbstractTlsPeer
    public JcaTlsCrypto getCrypto() {
        return this.manager.getContextData().getCrypto();
    }

    @Override // com.mi.car.jsse.easysec.tls.AbstractTlsServer, com.mi.car.jsse.easysec.tls.TlsServer
    public int[] getSupportedGroups() throws IOException {
        ProtocolVersion[] activeProtocolVersions = {this.context.getServerVersion()};
        this.jsseSecurityParameters.namedGroups = this.manager.getContextData().getNamedGroups(this.sslParameters, activeProtocolVersions);
        return NamedGroupInfo.getSupportedGroupsLocalServer(this.jsseSecurityParameters.namedGroups);
    }

    @Override // com.mi.car.jsse.easysec.tls.AbstractTlsServer, com.mi.car.jsse.easysec.tls.TlsServer
    public int getSelectedCipherSuite() throws IOException {
        List<SignatureSchemeInfo> signatureSchemes;
        ContextData contextData = this.manager.getContextData();
        SecurityParameters securityParameters = this.context.getSecurityParametersHandshake();
        NamedGroupInfo.notifyPeer(this.jsseSecurityParameters.namedGroups, securityParameters.getClientSupportedGroups());
        Vector<SignatureAndHashAlgorithm> clientSigAlgs = securityParameters.getClientSigAlgs();
        Vector<SignatureAndHashAlgorithm> clientSigAlgsCert = securityParameters.getClientSigAlgsCert();
        this.jsseSecurityParameters.peerSigSchemes = contextData.getSignatureSchemes(clientSigAlgs);
        JsseSecurityParameters jsseSecurityParameters2 = this.jsseSecurityParameters;
        if (clientSigAlgs == clientSigAlgsCert) {
            signatureSchemes = this.jsseSecurityParameters.peerSigSchemes;
        } else {
            signatureSchemes = contextData.getSignatureSchemes(clientSigAlgsCert);
        }
        jsseSecurityParameters2.peerSigSchemesCert = signatureSchemes;
        if (LOG.isLoggable(Level.FINEST)) {
            LOG.finest(JsseUtils.getSignatureAlgorithmsReport("Peer signature_algorithms", this.jsseSecurityParameters.peerSigSchemes));
            if (this.jsseSecurityParameters.peerSigSchemesCert != this.jsseSecurityParameters.peerSigSchemes) {
                LOG.finest(JsseUtils.getSignatureAlgorithmsReport("Peer signature_algorithms_cert", this.jsseSecurityParameters.peerSigSchemesCert));
            }
        }
        if (DummyX509KeyManager.INSTANCE == contextData.getX509KeyManager()) {
            throw new TlsFatalAlert((short) 40);
        }
        this.keyManagerMissCache = new HashSet();
        int selectedCipherSuite = super.getSelectedCipherSuite();
        this.keyManagerMissCache = null;
        LOG.fine("Server selected cipher suite: " + this.manager.getContextData().getContext().validateNegotiatedCipherSuite(this.sslParameters, selectedCipherSuite));
        return selectedCipherSuite;
    }

    @Override // com.mi.car.jsse.easysec.tls.AbstractTlsServer, com.mi.car.jsse.easysec.tls.TlsServer
    public Hashtable<Integer, byte[]> getServerExtensions() throws IOException {
        super.getServerExtensions();
        if (this.matchedSNIServerName != null) {
            TlsExtensionsUtils.addServerNameExtensionServer(this.serverExtensions);
        }
        return this.serverExtensions;
    }

    @Override // com.mi.car.jsse.easysec.tls.AbstractTlsServer, com.mi.car.jsse.easysec.tls.TlsServer
    public TlsSession getSessionToResume(byte[] sessionID) {
        ProvSSLSession availableSSLSession;
        ProvSSLSessionContext sslSessionContext = this.manager.getContextData().getServerSessionContext();
        if (provServerEnableSessionResumption && (availableSSLSession = sslSessionContext.getSessionImpl(sessionID)) != null) {
            TlsSession sessionToResume = availableSSLSession.getTlsSession();
            if (isResumable(availableSSLSession, sessionToResume)) {
                this.sslSession = availableSSLSession;
                return sessionToResume;
            }
        }
        JsseUtils.checkSessionCreationEnabled(this.manager);
        return null;
    }

    @Override // com.mi.car.jsse.easysec.tls.AbstractTlsServer, com.mi.car.jsse.easysec.tls.TlsServer
    public byte[] getNewSessionID() {
        if (!provServerEnableSessionResumption || TlsUtils.isTLSv13(this.context)) {
            return null;
        }
        return this.context.getNonceGenerator().generateNonce(32);
    }

    @Override // com.mi.car.jsse.easysec.tls.AbstractTlsServer, com.mi.car.jsse.easysec.tls.TlsServer
    public void notifySession(TlsSession session) {
        byte[] sessionID = session.getSessionID();
        if (this.sslSession != null && this.sslSession.getTlsSession() == session) {
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
        this.manager.notifyHandshakeSession(this.manager.getContextData().getServerSessionContext(), this.context.getSecurityParametersHandshake(), this.jsseSecurityParameters, this.sslSession);
    }

    @Override // com.mi.car.jsse.easysec.tls.TlsPeer, com.mi.car.jsse.easysec.tls.AbstractTlsPeer
    public void notifyAlertRaised(short alertLevel, short alertDescription, String message, Throwable cause) {
        Level level = alertLevel == 1 ? Level.FINE : alertDescription == 80 ? Level.WARNING : Level.INFO;
        if (LOG.isLoggable(level)) {
            String msg = JsseUtils.getAlertLogMessage("Server raised", alertLevel, alertDescription);
            if (message != null) {
                msg = msg + ": " + message;
            }
            LOG.log(level, msg, cause);
        }
    }

    @Override // com.mi.car.jsse.easysec.tls.TlsPeer, com.mi.car.jsse.easysec.tls.AbstractTlsPeer
    public void notifyAlertReceived(short alertLevel, short alertDescription) {
        super.notifyAlertReceived(alertLevel, alertDescription);
        Level level = alertLevel == 1 ? Level.FINE : Level.INFO;
        if (LOG.isLoggable(level)) {
            LOG.log(level, JsseUtils.getAlertLogMessage("Server received", alertLevel, alertDescription));
        }
    }

    @Override // com.mi.car.jsse.easysec.tls.AbstractTlsServer, com.mi.car.jsse.easysec.tls.TlsServer
    public ProtocolVersion getServerVersion() throws IOException {
        ProtocolVersion serverVersion = super.getServerVersion();
        LOG.fine("Server selected protocol version: " + this.manager.getContextData().getContext().validateNegotiatedProtocol(this.sslParameters, serverVersion));
        return serverVersion;
    }

    @Override // com.mi.car.jsse.easysec.tls.AbstractTlsServer, com.mi.car.jsse.easysec.tls.TlsServer
    public void notifyClientCertificate(Certificate clientCertificate) throws IOException {
        if (!isClientAuthEnabled()) {
            throw new TlsFatalAlert((short) 80);
        } else if (clientCertificate != null && !clientCertificate.isEmpty()) {
            this.manager.checkClientTrusted(JsseUtils.getX509CertificateChain(getCrypto(), clientCertificate), "TLS-client-auth");
        } else if (this.sslParameters.getNeedClientAuth()) {
            throw new TlsFatalAlert(TlsUtils.isTLSv13(this.context) ? AlertDescription.certificate_required : 40);
        }
    }

    @Override // com.mi.car.jsse.easysec.tls.TlsPeer, com.mi.car.jsse.easysec.tls.AbstractTlsPeer
    public synchronized void notifyHandshakeComplete() throws IOException {
        boolean addToCache = true;
        synchronized (this) {
            super.notifyHandshakeComplete();
            this.handshakeComplete = true;
            TlsSession connectionTlsSession = this.context.getSession();
            if (this.sslSession == null || this.sslSession.getTlsSession() != connectionTlsSession) {
                ProvSSLSessionContext sslSessionContext = this.manager.getContextData().getServerSessionContext();
                String peerHost = this.manager.getPeerHost();
                int peerPort = this.manager.getPeerPort();
                JsseSessionParameters jsseSessionParameters = new JsseSessionParameters(null, this.matchedSNIServerName);
                if (!provServerEnableSessionResumption || TlsUtils.isTLSv13(this.context) || !this.context.getSecurityParametersConnection().isExtendedMasterSecret()) {
                    addToCache = false;
                }
                this.sslSession = sslSessionContext.reportSession(peerHost, peerPort, connectionTlsSession, jsseSessionParameters, addToCache);
            }
            this.manager.notifyHandshakeComplete(new ProvSSLConnection(this.context, this.sslSession));
        }
    }

    @Override // com.mi.car.jsse.easysec.tls.TlsPeer, com.mi.car.jsse.easysec.tls.AbstractTlsPeer
    public void notifySecureRenegotiation(boolean secureRenegotiation) throws IOException {
        if (!secureRenegotiation && !PropertyUtils.getBooleanSystemProperty("sun.security.ssl.allowLegacyHelloMessages", true)) {
            throw new TlsFatalAlert((short) 40);
        }
    }

    @Override // com.mi.car.jsse.easysec.tls.AbstractTlsServer, com.mi.car.jsse.easysec.tls.TlsServer
    public void processClientExtensions(Hashtable clientExtensions) throws IOException {
        super.processClientExtensions(clientExtensions);
        Vector<ServerName> serverNameList = this.context.getSecurityParametersHandshake().getClientServerNames();
        if (serverNameList != null) {
            Collection<BCSNIMatcher> sniMatchers = this.sslParameters.getSNIMatchers();
            if (sniMatchers == null || sniMatchers.isEmpty()) {
                LOG.fine("Server ignored SNI (no matchers specified)");
            } else {
                this.matchedSNIServerName = JsseUtils.findMatchingSNIServerName(serverNameList, sniMatchers);
                if (this.matchedSNIServerName == null) {
                    throw new TlsFatalAlert(AlertDescription.unrecognized_name);
                }
                LOG.fine("Server accepted SNI: " + this.matchedSNIServerName);
            }
        }
        if (TlsUtils.isTLSv13(this.context)) {
            Vector<X500Name> certificateAuthorities = TlsExtensionsUtils.getCertificateAuthoritiesExtension(clientExtensions);
            this.jsseSecurityParameters.trustedIssuers = JsseUtils.toX500Principals(certificateAuthorities);
        } else if (provServerEnableTrustedCAKeys) {
            Vector<TrustedAuthority> trustedCAKeys = this.trustedCAKeys;
            this.jsseSecurityParameters.trustedIssuers = JsseUtils.getTrustedIssuers(trustedCAKeys);
        }
    }

    @Override // com.mi.car.jsse.easysec.tls.TlsPeer, com.mi.car.jsse.easysec.tls.AbstractTlsPeer
    public boolean requiresCloseNotify() {
        return JsseUtils.requireCloseNotify();
    }

    @Override // com.mi.car.jsse.easysec.tls.TlsPeer, com.mi.car.jsse.easysec.tls.AbstractTlsPeer
    public boolean requiresExtendedMasterSecret() {
        return !JsseUtils.allowLegacyMasterSecret();
    }

    @Override // com.mi.car.jsse.easysec.tls.TlsPeer, com.mi.car.jsse.easysec.tls.AbstractTlsPeer
    public boolean shouldUseExtendedMasterSecret() {
        return JsseUtils.useExtendedMasterSecret();
    }

    /* access modifiers changed from: protected */
    public boolean isClientAuthEnabled() {
        return this.sslParameters.getNeedClientAuth() || this.sslParameters.getWantClientAuth();
    }

    /* access modifiers changed from: protected */
    public boolean isResumable(ProvSSLSession provSSLSession, TlsSession tlsSession) {
        SessionParameters sessionParameters;
        if (tlsSession == null || !tlsSession.isResumable()) {
            return false;
        }
        ProtocolVersion negotiatedVersion = this.context.getSecurityParametersHandshake().getNegotiatedVersion();
        if (TlsUtils.isTLSv13(negotiatedVersion) || (sessionParameters = tlsSession.exportSessionParameters()) == null || !negotiatedVersion.equals(sessionParameters.getNegotiatedVersion()) || !Arrays.contains(getCipherSuites(), sessionParameters.getCipherSuite()) || !Arrays.contains(this.offeredCipherSuites, sessionParameters.getCipherSuite()) || !sessionParameters.isExtendedMasterSecret()) {
            return false;
        }
        JsseSessionParameters jsseSessionParameters = provSSLSession.getJsseSessionParameters();
        BCSNIServerName connectionSNI = this.matchedSNIServerName;
        BCSNIServerName sessionSNI = jsseSessionParameters.getMatchedSNIServerName();
        if (JsseUtils.equals(connectionSNI, sessionSNI)) {
            return true;
        }
        LOG.finest("Session not resumable - SNI mismatch; connection: " + connectionSNI + ", session: " + sessionSNI);
        return false;
    }

    /* access modifiers changed from: protected */
    public TlsCredentials selectCredentials(Principal[] issuers, int cipherSuite) throws IOException {
        int keyExchangeAlgorithm = TlsUtils.getKeyExchangeAlgorithm(cipherSuite);
        switch (keyExchangeAlgorithm) {
            case 0:
                return selectServerCredentials13(issuers, TlsUtils.EMPTY_BYTES);
            case 1:
            case 3:
            case 5:
            case 17:
            case 19:
                if (1 == keyExchangeAlgorithm || !TlsUtils.isSignatureAlgorithmsExtensionAllowed(this.context.getServerVersion())) {
                    return selectServerCredentialsLegacy(issuers, keyExchangeAlgorithm);
                }
                return selectServerCredentials12(issuers, keyExchangeAlgorithm);
            default:
                return null;
        }
    }

    /* access modifiers changed from: protected */
    public TlsCredentials selectServerCredentials12(Principal[] issuers, int keyExchangeAlgorithm) throws IOException {
        String keyType;
        BCAlgorithmConstraints algorithmConstraints = this.sslParameters.getAlgorithmConstraints();
        short legacySignatureAlgorithm = TlsUtils.getLegacySignatureAlgorithmServer(keyExchangeAlgorithm);
        LinkedHashMap<String, SignatureSchemeInfo> keyTypeMap = new LinkedHashMap<>();
        for (SignatureSchemeInfo signatureSchemeInfo : this.jsseSecurityParameters.peerSigSchemes) {
            if (TlsUtils.isValidSignatureSchemeForServerKeyExchange(signatureSchemeInfo.getSignatureScheme(), keyExchangeAlgorithm)) {
                if (legacySignatureAlgorithm == signatureSchemeInfo.getSignatureAlgorithm()) {
                    keyType = JsseUtils.getKeyTypeLegacyServer(keyExchangeAlgorithm);
                } else {
                    keyType = signatureSchemeInfo.getKeyType();
                }
                if (!this.keyManagerMissCache.contains(keyType) && !keyTypeMap.containsKey(keyType) && signatureSchemeInfo.isActive(algorithmConstraints, false, true, this.jsseSecurityParameters.namedGroups)) {
                    keyTypeMap.put(keyType, signatureSchemeInfo);
                }
            }
        }
        if (keyTypeMap.isEmpty()) {
            LOG.fine("Server (1.2) has no key types to try for KeyExchangeAlgorithm " + keyExchangeAlgorithm);
            return null;
        }
        BCX509Key x509Key = this.manager.chooseServerKey((String[]) keyTypeMap.keySet().toArray(TlsUtils.EMPTY_STRINGS), issuers);
        if (x509Key == null) {
            handleKeyManagerMisses(keyTypeMap, null);
            LOG.fine("Server (1.2) did not select any credentials for KeyExchangeAlgorithm " + keyExchangeAlgorithm);
            return null;
        }
        String selectedKeyType = x509Key.getKeyType();
        handleKeyManagerMisses(keyTypeMap, selectedKeyType);
        SignatureSchemeInfo selectedSignatureSchemeInfo = keyTypeMap.get(selectedKeyType);
        if (selectedSignatureSchemeInfo == null) {
            throw new TlsFatalAlert((short) 80, "Key manager returned invalid key type");
        }
        if (LOG.isLoggable(Level.FINE)) {
            LOG.fine("Server (1.2) selected credentials for signature scheme '" + selectedSignatureSchemeInfo + "' (keyType '" + selectedKeyType + "'), with private key algorithm '" + JsseUtils.getPrivateKeyAlgorithm(x509Key.getPrivateKey()) + "'");
        }
        return JsseUtils.createCredentialedSigner(this.context, getCrypto(), x509Key, selectedSignatureSchemeInfo.getSignatureAndHashAlgorithm());
    }

    /* access modifiers changed from: protected */
    public TlsCredentials selectServerCredentials13(Principal[] issuers, byte[] certificateRequestContext) throws IOException {
        BCAlgorithmConstraints algorithmConstraints = this.sslParameters.getAlgorithmConstraints();
        LinkedHashMap<String, SignatureSchemeInfo> keyTypeMap = new LinkedHashMap<>();
        for (SignatureSchemeInfo signatureSchemeInfo : this.jsseSecurityParameters.peerSigSchemes) {
            String keyType = signatureSchemeInfo.getKeyType13();
            if (!this.keyManagerMissCache.contains(keyType) && !keyTypeMap.containsKey(keyType) && signatureSchemeInfo.isActive(algorithmConstraints, true, false, this.jsseSecurityParameters.namedGroups)) {
                keyTypeMap.put(keyType, signatureSchemeInfo);
            }
        }
        if (keyTypeMap.isEmpty()) {
            LOG.fine("Server (1.3) found no usable signature schemes");
            return null;
        }
        BCX509Key x509Key = this.manager.chooseServerKey((String[]) keyTypeMap.keySet().toArray(TlsUtils.EMPTY_STRINGS), issuers);
        if (x509Key == null) {
            handleKeyManagerMisses(keyTypeMap, null);
            LOG.fine("Server (1.3) did not select any credentials");
            return null;
        }
        String selectedKeyType = x509Key.getKeyType();
        handleKeyManagerMisses(keyTypeMap, selectedKeyType);
        SignatureSchemeInfo selectedSignatureSchemeInfo = keyTypeMap.get(selectedKeyType);
        if (selectedSignatureSchemeInfo == null) {
            throw new TlsFatalAlert((short) 80, "Key manager returned invalid key type");
        }
        if (LOG.isLoggable(Level.FINE)) {
            LOG.fine("Server (1.3) selected credentials for signature scheme '" + selectedSignatureSchemeInfo + "' (keyType '" + selectedKeyType + "'), with private key algorithm '" + JsseUtils.getPrivateKeyAlgorithm(x509Key.getPrivateKey()) + "'");
        }
        return JsseUtils.createCredentialedSigner13(this.context, getCrypto(), x509Key, selectedSignatureSchemeInfo.getSignatureAndHashAlgorithm(), certificateRequestContext);
    }

    /* access modifiers changed from: protected */
    public TlsCredentials selectServerCredentialsLegacy(Principal[] issuers, int keyExchangeAlgorithm) throws IOException {
        String keyType = JsseUtils.getKeyTypeLegacyServer(keyExchangeAlgorithm);
        if (this.keyManagerMissCache.contains(keyType)) {
            return null;
        }
        BCX509Key x509Key = this.manager.chooseServerKey(new String[]{keyType}, issuers);
        if (x509Key == null) {
            this.keyManagerMissCache.add(keyType);
            return null;
        } else if (1 == keyExchangeAlgorithm) {
            return JsseUtils.createCredentialedDecryptor(getCrypto(), x509Key);
        } else {
            return JsseUtils.createCredentialedSigner(this.context, getCrypto(), x509Key, null);
        }
    }

    private void handleKeyManagerMisses(LinkedHashMap<String, SignatureSchemeInfo> keyTypeMap, String selectedKeyType) {
        for (Map.Entry<String, SignatureSchemeInfo> entry : keyTypeMap.entrySet()) {
            String keyType = entry.getKey();
            if (!keyType.equals(selectedKeyType)) {
                this.keyManagerMissCache.add(keyType);
                if (LOG.isLoggable(Level.FINER)) {
                    LOG.finer("Server found no credentials for signature scheme '" + entry.getValue() + "' (keyType '" + keyType + "')");
                }
            } else {
                return;
            }
        }
    }
}
