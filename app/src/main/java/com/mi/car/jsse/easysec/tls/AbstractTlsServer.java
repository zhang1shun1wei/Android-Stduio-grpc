package com.mi.car.jsse.easysec.tls;

import com.mi.car.jsse.easysec.tls.crypto.TlsCrypto;
import com.mi.car.jsse.easysec.tls.crypto.TlsDHConfig;
import com.mi.car.jsse.easysec.tls.crypto.TlsECConfig;
import java.io.IOException;
import java.util.Hashtable;
import java.util.Vector;

public abstract class AbstractTlsServer extends AbstractTlsPeer implements TlsServer {
    protected CertificateStatusRequest certificateStatusRequest;
    protected int[] cipherSuites;
    protected Hashtable clientExtensions;
    protected Vector clientProtocolNames;
    protected boolean clientSentECPointFormats;
    protected TlsServerContext context;
    protected boolean encryptThenMACOffered;
    protected short maxFragmentLengthOffered;
    protected int[] offeredCipherSuites;
    protected ProtocolVersion[] protocolVersions;
    protected int selectedCipherSuite;
    protected ProtocolName selectedProtocolName;
    protected final Hashtable serverExtensions = new Hashtable();
    protected Vector statusRequestV2;
    protected boolean truncatedHMacOffered;
    protected Vector trustedCAKeys;

    public AbstractTlsServer(TlsCrypto crypto) {
        super(crypto);
    }

    /* access modifiers changed from: protected */
    public boolean allowCertificateStatus() {
        return true;
    }

    /* access modifiers changed from: protected */
    public boolean allowEncryptThenMAC() {
        return true;
    }

    /* access modifiers changed from: protected */
    public boolean allowMultiCertStatus() {
        return false;
    }

    /* access modifiers changed from: protected */
    public boolean allowTruncatedHMac() {
        return false;
    }

    /* access modifiers changed from: protected */
    public boolean allowTrustedCAIndication() {
        return false;
    }

    /* access modifiers changed from: protected */
    public Hashtable checkServerExtensions() {
        return this.serverExtensions;
    }

    /* access modifiers changed from: protected */
    public int getMaximumNegotiableCurveBits() {
        int[] clientSupportedGroups = this.context.getSecurityParametersHandshake().getClientSupportedGroups();
        if (clientSupportedGroups == null) {
            return NamedGroup.getMaximumCurveBits();
        }
        int maxBits = 0;
        for (int i : clientSupportedGroups) {
            maxBits = Math.max(maxBits, NamedGroup.getCurveBits(i));
        }
        return maxBits;
    }

    /* access modifiers changed from: protected */
    public int getMaximumNegotiableFiniteFieldBits() {
        int[] clientSupportedGroups = this.context.getSecurityParametersHandshake().getClientSupportedGroups();
        if (clientSupportedGroups == null) {
            return NamedGroup.getMaximumFiniteFieldBits();
        }
        int maxBits = 0;
        for (int i : clientSupportedGroups) {
            maxBits = Math.max(maxBits, NamedGroup.getFiniteFieldBits(i));
        }
        return maxBits;
    }

    /* access modifiers changed from: protected */
    public Vector getProtocolNames() {
        return null;
    }

    /* access modifiers changed from: protected */
    public boolean isSelectableCipherSuite(int cipherSuite, int availCurveBits, int availFiniteFieldBits, Vector sigAlgs) {
        return TlsUtils.isValidVersionForCipherSuite(cipherSuite, this.context.getServerVersion()) && availCurveBits >= TlsECCUtils.getMinimumCurveBits(cipherSuite) && availFiniteFieldBits >= TlsDHUtils.getMinimumFiniteFieldBits(cipherSuite) && TlsUtils.isValidCipherSuiteForSignatureAlgorithms(cipherSuite, sigAlgs);
    }

    /* access modifiers changed from: protected */
    public boolean preferLocalCipherSuites() {
        return false;
    }

    /* access modifiers changed from: protected */
    public boolean selectCipherSuite(int cipherSuite) throws IOException {
        this.selectedCipherSuite = cipherSuite;
        return true;
    }

    /* access modifiers changed from: protected */
    public int selectDH(int minimumFiniteFieldBits) {
        int[] clientSupportedGroups = this.context.getSecurityParametersHandshake().getClientSupportedGroups();
        if (clientSupportedGroups == null) {
            return selectDHDefault(minimumFiniteFieldBits);
        }
        for (int namedGroup : clientSupportedGroups) {
            if (NamedGroup.getFiniteFieldBits(namedGroup) >= minimumFiniteFieldBits) {
                return namedGroup;
            }
        }
        return -1;
    }

    /* access modifiers changed from: protected */
    public int selectDHDefault(int minimumFiniteFieldBits) {
        if (minimumFiniteFieldBits <= 2048) {
            return NamedGroup.ffdhe2048;
        }
        if (minimumFiniteFieldBits <= 3072) {
            return NamedGroup.ffdhe3072;
        }
        if (minimumFiniteFieldBits <= 4096) {
            return NamedGroup.ffdhe4096;
        }
        if (minimumFiniteFieldBits <= 6144) {
            return NamedGroup.ffdhe6144;
        }
        if (minimumFiniteFieldBits <= 8192) {
            return NamedGroup.ffdhe8192;
        }
        return -1;
    }

    /* access modifiers changed from: protected */
    public int selectECDH(int minimumCurveBits) {
        int[] clientSupportedGroups = this.context.getSecurityParametersHandshake().getClientSupportedGroups();
        if (clientSupportedGroups == null) {
            return selectECDHDefault(minimumCurveBits);
        }
        for (int namedGroup : clientSupportedGroups) {
            if (NamedGroup.getCurveBits(namedGroup) >= minimumCurveBits) {
                return namedGroup;
            }
        }
        return -1;
    }

    /* access modifiers changed from: protected */
    public int selectECDHDefault(int minimumCurveBits) {
        if (minimumCurveBits <= 256) {
            return 23;
        }
        if (minimumCurveBits <= 384) {
            return 24;
        }
        return minimumCurveBits <= 521 ? 25 : -1;
    }

    /* access modifiers changed from: protected */
    public ProtocolName selectProtocolName() throws IOException {
        Vector serverProtocolNames = getProtocolNames();
        if (serverProtocolNames == null || serverProtocolNames.isEmpty()) {
            return null;
        }
        ProtocolName result = selectProtocolName(this.clientProtocolNames, serverProtocolNames);
        if (result != null) {
            return result;
        }
        throw new TlsFatalAlert(AlertDescription.no_application_protocol);
    }

    /* access modifiers changed from: protected */
    public ProtocolName selectProtocolName(Vector clientProtocolNames2, Vector serverProtocolNames) {
        for (int i = 0; i < serverProtocolNames.size(); i++) {
            ProtocolName serverProtocolName = (ProtocolName) serverProtocolNames.elementAt(i);
            if (clientProtocolNames2.contains(serverProtocolName)) {
                return serverProtocolName;
            }
        }
        return null;
    }

    /* access modifiers changed from: protected */
    public boolean shouldSelectProtocolNameEarly() {
        return true;
    }

    @Override // com.mi.car.jsse.easysec.tls.TlsServer
    public void init(TlsServerContext context2) {
        this.context = context2;
        this.protocolVersions = getSupportedVersions();
        this.cipherSuites = getSupportedCipherSuites();
    }

    @Override // com.mi.car.jsse.easysec.tls.TlsPeer
    public ProtocolVersion[] getProtocolVersions() {
        return this.protocolVersions;
    }

    @Override // com.mi.car.jsse.easysec.tls.TlsPeer
    public int[] getCipherSuites() {
        return this.cipherSuites;
    }

    @Override // com.mi.car.jsse.easysec.tls.TlsPeer, com.mi.car.jsse.easysec.tls.AbstractTlsPeer
    public void notifyHandshakeBeginning() throws IOException {
        super.notifyHandshakeBeginning();
        this.offeredCipherSuites = null;
        this.clientExtensions = null;
        this.encryptThenMACOffered = false;
        this.maxFragmentLengthOffered = 0;
        this.truncatedHMacOffered = false;
        this.clientSentECPointFormats = false;
        this.certificateStatusRequest = null;
        this.selectedCipherSuite = -1;
        this.selectedProtocolName = null;
        this.serverExtensions.clear();
    }

    @Override // com.mi.car.jsse.easysec.tls.TlsServer
    public TlsSession getSessionToResume(byte[] sessionID) {
        return null;
    }

    @Override // com.mi.car.jsse.easysec.tls.TlsServer
    public byte[] getNewSessionID() {
        return null;
    }

    @Override // com.mi.car.jsse.easysec.tls.TlsServer
    public TlsPSKExternal getExternalPSK(Vector identities) {
        return null;
    }

    @Override // com.mi.car.jsse.easysec.tls.TlsServer
    public void notifySession(TlsSession session) {
    }

    @Override // com.mi.car.jsse.easysec.tls.TlsServer
    public void notifyClientVersion(ProtocolVersion clientVersion) throws IOException {
    }

    @Override // com.mi.car.jsse.easysec.tls.TlsServer
    public void notifyFallback(boolean isFallback) throws IOException {
        ProtocolVersion latestServerVersion;
        if (isFallback) {
            ProtocolVersion[] serverVersions = getProtocolVersions();
            ProtocolVersion clientVersion = this.context.getClientVersion();
            if (clientVersion.isTLS()) {
                latestServerVersion = ProtocolVersion.getLatestTLS(serverVersions);
            } else if (clientVersion.isDTLS()) {
                latestServerVersion = ProtocolVersion.getLatestDTLS(serverVersions);
            } else {
                throw new TlsFatalAlert((short) 80);
            }
            if (latestServerVersion != null && latestServerVersion.isLaterVersionOf(clientVersion)) {
                throw new TlsFatalAlert((short) 86);
            }
        }
    }

    @Override // com.mi.car.jsse.easysec.tls.TlsServer
    public void notifyOfferedCipherSuites(int[] offeredCipherSuites2) throws IOException {
        this.offeredCipherSuites = offeredCipherSuites2;
    }

    @Override // com.mi.car.jsse.easysec.tls.TlsServer
    public void processClientExtensions(Hashtable clientExtensions2) throws IOException {
        this.clientExtensions = clientExtensions2;
        if (clientExtensions2 != null) {
            this.clientProtocolNames = TlsExtensionsUtils.getALPNExtensionClient(clientExtensions2);
            if (shouldSelectProtocolNameEarly() && this.clientProtocolNames != null && !this.clientProtocolNames.isEmpty()) {
                this.selectedProtocolName = selectProtocolName();
            }
            this.encryptThenMACOffered = TlsExtensionsUtils.hasEncryptThenMACExtension(clientExtensions2);
            this.truncatedHMacOffered = TlsExtensionsUtils.hasTruncatedHMacExtension(clientExtensions2);
            this.statusRequestV2 = TlsExtensionsUtils.getStatusRequestV2Extension(clientExtensions2);
            this.trustedCAKeys = TlsExtensionsUtils.getTrustedCAKeysExtensionClient(clientExtensions2);
            this.clientSentECPointFormats = TlsExtensionsUtils.getSupportedPointFormatsExtension(clientExtensions2) != null;
            this.certificateStatusRequest = TlsExtensionsUtils.getStatusRequestExtension(clientExtensions2);
            this.maxFragmentLengthOffered = TlsExtensionsUtils.getMaxFragmentLengthExtension(clientExtensions2);
            if (this.maxFragmentLengthOffered >= 0 && !MaxFragmentLength.isValid(this.maxFragmentLengthOffered)) {
                throw new TlsFatalAlert((short) 47);
            }
        }
    }

    @Override // com.mi.car.jsse.easysec.tls.TlsServer
    public ProtocolVersion getServerVersion() throws IOException {
        ProtocolVersion[] serverVersions = getProtocolVersions();
        ProtocolVersion[] clientVersions = this.context.getClientSupportedVersions();
        for (ProtocolVersion clientVersion : clientVersions) {
            if (ProtocolVersion.contains(serverVersions, clientVersion)) {
                return clientVersion;
            }
        }
        throw new TlsFatalAlert((short) 70);
    }

    @Override // com.mi.car.jsse.easysec.tls.TlsServer
    public int[] getSupportedGroups() throws IOException {
        return new int[]{29, 30, 23, 24, NamedGroup.ffdhe2048, NamedGroup.ffdhe3072, NamedGroup.ffdhe4096};
    }

    @Override // com.mi.car.jsse.easysec.tls.TlsServer
    public int getSelectedCipherSuite() throws IOException {
        SecurityParameters securityParameters = this.context.getSecurityParametersHandshake();
        ProtocolVersion negotiatedVersion = securityParameters.getNegotiatedVersion();
        if (TlsUtils.isTLSv13(negotiatedVersion)) {
            int commonCipherSuite13 = TlsUtils.getCommonCipherSuite13(negotiatedVersion, this.offeredCipherSuites, getCipherSuites(), preferLocalCipherSuites());
            if (commonCipherSuite13 >= 0 && selectCipherSuite(commonCipherSuite13)) {
                return commonCipherSuite13;
            }
        } else {
            Vector sigAlgs = TlsUtils.getUsableSignatureAlgorithms(securityParameters.getClientSigAlgs());
            int availCurveBits = getMaximumNegotiableCurveBits();
            int availFiniteFieldBits = getMaximumNegotiableFiniteFieldBits();
            int[] cipherSuites2 = TlsUtils.getCommonCipherSuites(this.offeredCipherSuites, getCipherSuites(), preferLocalCipherSuites());
            for (int cipherSuite : cipherSuites2) {
                if (isSelectableCipherSuite(cipherSuite, availCurveBits, availFiniteFieldBits, sigAlgs) && selectCipherSuite(cipherSuite)) {
                    return cipherSuite;
                }
            }
        }
        throw new TlsFatalAlert((short) 40, "No selectable cipher suite");
    }

    @Override // com.mi.car.jsse.easysec.tls.TlsServer
    public Hashtable getServerExtensions() throws IOException {
        if (!TlsUtils.isTLSv13(this.context)) {
            if (this.encryptThenMACOffered && allowEncryptThenMAC() && TlsUtils.isBlockCipherSuite(this.selectedCipherSuite)) {
                TlsExtensionsUtils.addEncryptThenMACExtension(this.serverExtensions);
            }
            if (this.truncatedHMacOffered && allowTruncatedHMac()) {
                TlsExtensionsUtils.addTruncatedHMacExtension(this.serverExtensions);
            }
            if (this.clientSentECPointFormats && TlsECCUtils.isECCCipherSuite(this.selectedCipherSuite)) {
                TlsExtensionsUtils.addSupportedPointFormatsExtension(this.serverExtensions, new short[]{0});
            }
            if (this.statusRequestV2 != null && allowMultiCertStatus()) {
                TlsExtensionsUtils.addEmptyExtensionData(this.serverExtensions, TlsExtensionsUtils.EXT_status_request_v2);
            } else if (this.certificateStatusRequest != null && allowCertificateStatus()) {
                TlsExtensionsUtils.addEmptyExtensionData(this.serverExtensions, TlsExtensionsUtils.EXT_status_request);
            }
            if (this.trustedCAKeys != null && allowTrustedCAIndication()) {
                TlsExtensionsUtils.addTrustedCAKeysExtensionServer(this.serverExtensions);
            }
        } else if (this.certificateStatusRequest == null || !allowCertificateStatus()) {
        }
        if (this.maxFragmentLengthOffered >= 0 && MaxFragmentLength.isValid(this.maxFragmentLengthOffered)) {
            TlsExtensionsUtils.addMaxFragmentLengthExtension(this.serverExtensions, this.maxFragmentLengthOffered);
        }
        return this.serverExtensions;
    }

    @Override // com.mi.car.jsse.easysec.tls.TlsServer
    public void getServerExtensionsForConnection(Hashtable serverExtensions2) throws IOException {
        if (!shouldSelectProtocolNameEarly() && this.clientProtocolNames != null && !this.clientProtocolNames.isEmpty()) {
            this.selectedProtocolName = selectProtocolName();
        }
        if (this.selectedProtocolName == null) {
            serverExtensions2.remove(TlsExtensionsUtils.EXT_application_layer_protocol_negotiation);
        } else {
            TlsExtensionsUtils.addALPNExtensionServer(serverExtensions2, this.selectedProtocolName);
        }
    }

    @Override // com.mi.car.jsse.easysec.tls.TlsServer
    public Vector getServerSupplementalData() throws IOException {
        return null;
    }

    @Override // com.mi.car.jsse.easysec.tls.TlsServer
    public CertificateStatus getCertificateStatus() throws IOException {
        return null;
    }

    @Override // com.mi.car.jsse.easysec.tls.TlsServer
    public CertificateRequest getCertificateRequest() throws IOException {
        return null;
    }

    @Override // com.mi.car.jsse.easysec.tls.TlsServer
    public TlsPSKIdentityManager getPSKIdentityManager() throws IOException {
        return null;
    }

    @Override // com.mi.car.jsse.easysec.tls.TlsServer
    public TlsSRPLoginParameters getSRPLoginParameters() throws IOException {
        return null;
    }

    @Override // com.mi.car.jsse.easysec.tls.TlsServer
    public TlsDHConfig getDHConfig() throws IOException {
        return TlsDHUtils.createNamedDHConfig(this.context, selectDH(TlsDHUtils.getMinimumFiniteFieldBits(this.selectedCipherSuite)));
    }

    @Override // com.mi.car.jsse.easysec.tls.TlsServer
    public TlsECConfig getECDHConfig() throws IOException {
        return TlsECCUtils.createNamedECConfig(this.context, selectECDH(TlsECCUtils.getMinimumCurveBits(this.selectedCipherSuite)));
    }

    @Override // com.mi.car.jsse.easysec.tls.TlsServer
    public void processClientSupplementalData(Vector clientSupplementalData) throws IOException {
        if (clientSupplementalData != null) {
            throw new TlsFatalAlert((short) 10);
        }
    }

    @Override // com.mi.car.jsse.easysec.tls.TlsServer
    public void notifyClientCertificate(Certificate clientCertificate) throws IOException {
        throw new TlsFatalAlert((short) 80);
    }

    @Override // com.mi.car.jsse.easysec.tls.TlsServer
    public NewSessionTicket getNewSessionTicket() throws IOException {
        return new NewSessionTicket(0, TlsUtils.EMPTY_BYTES);
    }
}
