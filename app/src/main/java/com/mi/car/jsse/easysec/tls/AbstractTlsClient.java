package com.mi.car.jsse.easysec.tls;

import com.mi.car.jsse.easysec.asn1.x509.Extensions;
import com.mi.car.jsse.easysec.tls.crypto.TlsCrypto;
import com.mi.car.jsse.easysec.util.Integers;
import java.io.IOException;
import java.util.Hashtable;
import java.util.Vector;

public abstract class AbstractTlsClient extends AbstractTlsPeer implements TlsClient {
    protected TlsClientContext context;
    protected ProtocolVersion[] protocolVersions;
    protected int[] cipherSuites;
    protected Vector supportedGroups;
    protected Vector supportedSignatureAlgorithms;
    protected Vector supportedSignatureAlgorithmsCert;

    public AbstractTlsClient(TlsCrypto crypto) {
        super(crypto);
    }

    protected boolean allowUnexpectedServerExtension(Integer extensionType, byte[] extensionData) throws IOException {
        switch(extensionType) {
            case 10:
                TlsExtensionsUtils.readSupportedGroupsExtension(extensionData);
                return true;
            case 11:
                TlsExtensionsUtils.readSupportedPointFormatsExtension(extensionData);
                return true;
            default:
                return false;
        }
    }

    protected Vector getNamedGroupRoles() {
        Vector namedGroupRoles = TlsUtils.getNamedGroupRoles(this.getCipherSuites());
        Vector sigAlgs = this.supportedSignatureAlgorithms;
        Vector sigAlgsCert = this.supportedSignatureAlgorithmsCert;
        if (null == sigAlgs || TlsUtils.containsAnySignatureAlgorithm(sigAlgs, (short)3) || null != sigAlgsCert && TlsUtils.containsAnySignatureAlgorithm(sigAlgsCert, (short)3)) {
            TlsUtils.addToSet(namedGroupRoles, 3);
        }

        return namedGroupRoles;
    }

    protected void checkForUnexpectedServerExtension(Hashtable serverExtensions, Integer extensionType) throws IOException {
        byte[] extensionData = TlsUtils.getExtensionData(serverExtensions, extensionType);
        if (extensionData != null && !this.allowUnexpectedServerExtension(extensionType, extensionData)) {
            throw new TlsFatalAlert((short)47);
        }
    }

    public TlsPSKIdentity getPSKIdentity() throws IOException {
        return null;
    }

    public TlsSRPIdentity getSRPIdentity() throws IOException {
        return null;
    }

    public TlsDHGroupVerifier getDHGroupVerifier() {
        return new DefaultTlsDHGroupVerifier();
    }

    public TlsSRPConfigVerifier getSRPConfigVerifier() {
        return new DefaultTlsSRPConfigVerifier();
    }

    protected Vector getCertificateAuthorities() {
        return null;
    }

    protected Vector getProtocolNames() {
        return null;
    }

    protected CertificateStatusRequest getCertificateStatusRequest() {
        return new CertificateStatusRequest((short)1, new OCSPStatusRequest((Vector)null, (Extensions)null));
    }

    protected Vector getMultiCertStatusRequest() {
        return null;
    }

    protected Vector getSNIServerNames() {
        return null;
    }

    protected Vector getSupportedGroups(Vector namedGroupRoles) {
        TlsCrypto crypto = this.getCrypto();
        Vector supportedGroups = new Vector();
        if (namedGroupRoles.contains(Integers.valueOf(2))) {
            TlsUtils.addIfSupported(supportedGroups, crypto, new int[]{29, 30});
        }

        if (namedGroupRoles.contains(Integers.valueOf(2)) || namedGroupRoles.contains(Integers.valueOf(3))) {
            TlsUtils.addIfSupported(supportedGroups, crypto, new int[]{23, 24});
        }

        if (namedGroupRoles.contains(Integers.valueOf(1))) {
            TlsUtils.addIfSupported(supportedGroups, crypto, new int[]{256, 257, 258});
        }

        return supportedGroups;
    }

    protected Vector getSupportedSignatureAlgorithms() {
        return TlsUtils.getDefaultSupportedSignatureAlgorithms(this.context);
    }

    protected Vector getSupportedSignatureAlgorithmsCert() {
        return null;
    }

    protected Vector getTrustedCAIndication() {
        return null;
    }

    public void init(TlsClientContext context) {
        this.context = context;
        this.protocolVersions = this.getSupportedVersions();
        this.cipherSuites = this.getSupportedCipherSuites();
    }

    public ProtocolVersion[] getProtocolVersions() {
        return this.protocolVersions;
    }

    public int[] getCipherSuites() {
        return this.cipherSuites;
    }

    public void notifyHandshakeBeginning() throws IOException {
        super.notifyHandshakeBeginning();
        this.supportedGroups = null;
        this.supportedSignatureAlgorithms = null;
        this.supportedSignatureAlgorithmsCert = null;
    }

    public TlsSession getSessionToResume() {
        return null;
    }

    public Vector getExternalPSKs() {
        return null;
    }

    public boolean isFallback() {
        return false;
    }

    public Hashtable getClientExtensions() throws IOException {
        Hashtable clientExtensions = new Hashtable();
        boolean offeringTLSv13Plus = false;
        boolean offeringPreTLSv13 = false;
        ProtocolVersion[] supportedVersions = this.getProtocolVersions();

        for(int i = 0; i < supportedVersions.length; ++i) {
            if (TlsUtils.isTLSv13(supportedVersions[i])) {
                offeringTLSv13Plus = true;
            } else {
                offeringPreTLSv13 = true;
            }
        }

        Vector protocolNames = this.getProtocolNames();
        if (protocolNames != null) {
            TlsExtensionsUtils.addALPNExtensionClient(clientExtensions, protocolNames);
        }

        Vector sniServerNames = this.getSNIServerNames();
        if (sniServerNames != null) {
            TlsExtensionsUtils.addServerNameExtensionClient(clientExtensions, sniServerNames);
        }

        CertificateStatusRequest statusRequest = this.getCertificateStatusRequest();
        if (statusRequest != null) {
            TlsExtensionsUtils.addStatusRequestExtension(clientExtensions, statusRequest);
        }

        Vector statusRequestV2;
        if (offeringTLSv13Plus) {
            statusRequestV2 = this.getCertificateAuthorities();
            if (statusRequestV2 != null) {
                TlsExtensionsUtils.addCertificateAuthoritiesExtension(clientExtensions, statusRequestV2);
            }
        }

        Vector namedGroupRoles;
        if (offeringPreTLSv13) {
            TlsExtensionsUtils.addEncryptThenMACExtension(clientExtensions);
            statusRequestV2 = this.getMultiCertStatusRequest();
            if (statusRequestV2 != null) {
                TlsExtensionsUtils.addStatusRequestV2Extension(clientExtensions, statusRequestV2);
            }

            namedGroupRoles = this.getTrustedCAIndication();
            if (namedGroupRoles != null) {
                TlsExtensionsUtils.addTrustedCAKeysExtensionClient(clientExtensions, namedGroupRoles);
            }
        }

        ProtocolVersion clientVersion = this.context.getClientVersion();
        Vector supportedSigAlgsCert;
        if (TlsUtils.isSignatureAlgorithmsExtensionAllowed(clientVersion)) {
            namedGroupRoles = this.getSupportedSignatureAlgorithms();
            if (null != namedGroupRoles && !namedGroupRoles.isEmpty()) {
                this.supportedSignatureAlgorithms = namedGroupRoles;
                TlsExtensionsUtils.addSignatureAlgorithmsExtension(clientExtensions, namedGroupRoles);
            }

            supportedSigAlgsCert = this.getSupportedSignatureAlgorithmsCert();
            if (null != supportedSigAlgsCert && !supportedSigAlgsCert.isEmpty()) {
                this.supportedSignatureAlgorithmsCert = supportedSigAlgsCert;
                TlsExtensionsUtils.addSignatureAlgorithmsCertExtension(clientExtensions, supportedSigAlgsCert);
            }
        }

        namedGroupRoles = this.getNamedGroupRoles();
        supportedSigAlgsCert = this.getSupportedGroups(namedGroupRoles);
        if (supportedSigAlgsCert != null && !supportedSigAlgsCert.isEmpty()) {
            this.supportedGroups = supportedSigAlgsCert;
            TlsExtensionsUtils.addSupportedGroupsExtension(clientExtensions, supportedSigAlgsCert);
        }

        if (offeringPreTLSv13 && (namedGroupRoles.contains(Integers.valueOf(2)) || namedGroupRoles.contains(Integers.valueOf(3)))) {
            TlsExtensionsUtils.addSupportedPointFormatsExtension(clientExtensions, new short[]{0});
        }

        return clientExtensions;
    }

    public Vector getEarlyKeyShareGroups() {
        if (null != this.supportedGroups && !this.supportedGroups.isEmpty()) {
            if (this.supportedGroups.contains(Integers.valueOf(29))) {
                return TlsUtils.vectorOfOne(Integers.valueOf(29));
            } else {
                return this.supportedGroups.contains(Integers.valueOf(23)) ? TlsUtils.vectorOfOne(Integers.valueOf(23)) : TlsUtils.vectorOfOne(this.supportedGroups.elementAt(0));
            }
        } else {
            return null;
        }
    }

    public void notifyServerVersion(ProtocolVersion serverVersion) throws IOException {
    }

    public void notifySessionToResume(TlsSession session) {
    }

    public void notifySessionID(byte[] sessionID) {
    }

    public void notifySelectedCipherSuite(int selectedCipherSuite) {
    }

    public void notifySelectedPSK(TlsPSK selectedPSK) throws IOException {
    }

    public void processServerExtensions(Hashtable serverExtensions) throws IOException {
        if (null != serverExtensions) {
            SecurityParameters securityParameters = this.context.getSecurityParametersHandshake();
            boolean isTLSv13 = TlsUtils.isTLSv13(securityParameters.getNegotiatedVersion());
            if (!isTLSv13) {
                this.checkForUnexpectedServerExtension(serverExtensions, TlsExtensionsUtils.EXT_signature_algorithms);
                this.checkForUnexpectedServerExtension(serverExtensions, TlsExtensionsUtils.EXT_signature_algorithms_cert);
                this.checkForUnexpectedServerExtension(serverExtensions, TlsExtensionsUtils.EXT_supported_groups);
                int selectedCipherSuite = securityParameters.getCipherSuite();
                if (TlsECCUtils.isECCCipherSuite(selectedCipherSuite)) {
                    TlsExtensionsUtils.getSupportedPointFormatsExtension(serverExtensions);
                } else {
                    this.checkForUnexpectedServerExtension(serverExtensions, TlsExtensionsUtils.EXT_ec_point_formats);
                }

                this.checkForUnexpectedServerExtension(serverExtensions, TlsExtensionsUtils.EXT_padding);
            }

        }
    }

    public void processServerSupplementalData(Vector serverSupplementalData) throws IOException {
        if (serverSupplementalData != null) {
            throw new TlsFatalAlert((short)10);
        }
    }

    public Vector getClientSupplementalData() throws IOException {
        return null;
    }

    public void notifyNewSessionTicket(NewSessionTicket newSessionTicket) throws IOException {
    }
}
