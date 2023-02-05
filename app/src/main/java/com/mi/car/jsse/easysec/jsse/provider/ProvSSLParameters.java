package com.mi.car.jsse.easysec.jsse.provider;

import com.mi.car.jsse.easysec.jsse.BCApplicationProtocolSelector;
import com.mi.car.jsse.easysec.jsse.BCSNIMatcher;
import com.mi.car.jsse.easysec.jsse.BCSNIServerName;
import com.mi.car.jsse.easysec.jsse.java.security.BCAlgorithmConstraints;
import com.mi.car.jsse.easysec.tls.TlsUtils;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLSocket;

/* access modifiers changed from: package-private */
public final class ProvSSLParameters {
    private BCAlgorithmConstraints algorithmConstraints = ProvAlgorithmConstraints.DEFAULT;
    private String[] applicationProtocols = TlsUtils.EMPTY_STRINGS;
    private String[] cipherSuites;
    private final ProvSSLContextSpi context;
    private String endpointIdentificationAlgorithm;
    private BCApplicationProtocolSelector<SSLEngine> engineAPSelector;
    private int maximumPacketSize = 0;
    private boolean needClientAuth = false;
    private String[] protocols;
    private ProvSSLSession sessionToResume;
    private List<BCSNIMatcher> sniMatchers;
    private List<BCSNIServerName> sniServerNames;
    private BCApplicationProtocolSelector<SSLSocket> socketAPSelector;
    private boolean useCipherSuitesOrder = true;
    private boolean wantClientAuth = false;

    private static <T> List<T> copyList(Collection<T> list) {
        if (list == null) {
            return null;
        }
        if (list.isEmpty()) {
            return Collections.emptyList();
        }
        return Collections.unmodifiableList(new ArrayList(list));
    }

    ProvSSLParameters(ProvSSLContextSpi context2, String[] cipherSuites2, String[] protocols2) {
        this.context = context2;
        this.cipherSuites = cipherSuites2;
        this.protocols = protocols2;
    }

    /* access modifiers changed from: package-private */
    public ProvSSLParameters copy() {
        ProvSSLParameters p = new ProvSSLParameters(this.context, this.cipherSuites, this.protocols);
        p.needClientAuth = this.needClientAuth;
        p.wantClientAuth = this.wantClientAuth;
        p.algorithmConstraints = this.algorithmConstraints;
        p.endpointIdentificationAlgorithm = this.endpointIdentificationAlgorithm;
        p.useCipherSuitesOrder = this.useCipherSuitesOrder;
        p.sniMatchers = this.sniMatchers;
        p.sniServerNames = this.sniServerNames;
        p.applicationProtocols = this.applicationProtocols;
        p.engineAPSelector = this.engineAPSelector;
        p.socketAPSelector = this.socketAPSelector;
        p.sessionToResume = this.sessionToResume;
        return p;
    }

    /* access modifiers changed from: package-private */
    public ProvSSLParameters copyForConnection() {
        ProvSSLParameters p = copy();
        if (ProvAlgorithmConstraints.DEFAULT != p.algorithmConstraints) {
            p.algorithmConstraints = new ProvAlgorithmConstraints(p.algorithmConstraints, true);
        }
        return p;
    }

    public String[] getCipherSuites() {
        return (String[]) this.cipherSuites.clone();
    }

    /* access modifiers changed from: package-private */
    public String[] getCipherSuitesArray() {
        return this.cipherSuites;
    }

    public void setCipherSuites(String[] cipherSuites2) {
        this.cipherSuites = this.context.getSupportedCipherSuites(cipherSuites2);
    }

    /* access modifiers changed from: package-private */
    public void setCipherSuitesArray(String[] cipherSuites2) {
        this.cipherSuites = cipherSuites2;
    }

    public String[] getProtocols() {
        return (String[]) this.protocols.clone();
    }

    /* access modifiers changed from: package-private */
    public String[] getProtocolsArray() {
        return this.protocols;
    }

    public void setProtocols(String[] protocols2) {
        if (!this.context.isSupportedProtocols(protocols2)) {
            throw new IllegalArgumentException("'protocols' cannot be null, or contain unsupported protocols");
        }
        this.protocols = (String[]) protocols2.clone();
    }

    /* access modifiers changed from: package-private */
    public void setProtocolsArray(String[] protocols2) {
        this.protocols = protocols2;
    }

    public boolean getNeedClientAuth() {
        return this.needClientAuth;
    }

    public void setNeedClientAuth(boolean needClientAuth2) {
        this.needClientAuth = needClientAuth2;
        this.wantClientAuth = false;
    }

    public boolean getWantClientAuth() {
        return this.wantClientAuth;
    }

    public void setWantClientAuth(boolean wantClientAuth2) {
        this.needClientAuth = false;
        this.wantClientAuth = wantClientAuth2;
    }

    public BCAlgorithmConstraints getAlgorithmConstraints() {
        return this.algorithmConstraints;
    }

    public void setAlgorithmConstraints(BCAlgorithmConstraints algorithmConstraints2) {
        this.algorithmConstraints = algorithmConstraints2;
    }

    public String getEndpointIdentificationAlgorithm() {
        return this.endpointIdentificationAlgorithm;
    }

    public void setEndpointIdentificationAlgorithm(String endpointIdentificationAlgorithm2) {
        this.endpointIdentificationAlgorithm = endpointIdentificationAlgorithm2;
    }

    public boolean getUseCipherSuitesOrder() {
        return this.useCipherSuitesOrder;
    }

    public void setUseCipherSuitesOrder(boolean useCipherSuitesOrder2) {
        this.useCipherSuitesOrder = useCipherSuitesOrder2;
    }

    public int getMaximumPacketSize() {
        return this.maximumPacketSize;
    }

    public void setMaximumPacketSize(int maximumPacketSize2) {
        if (maximumPacketSize2 < 0) {
            throw new IllegalArgumentException("The maximum packet size cannot be negative");
        }
        this.maximumPacketSize = maximumPacketSize2;
    }

    public List<BCSNIServerName> getServerNames() {
        return copyList(this.sniServerNames);
    }

    public void setServerNames(List<BCSNIServerName> serverNames) {
        this.sniServerNames = copyList(serverNames);
    }

    public Collection<BCSNIMatcher> getSNIMatchers() {
        return copyList(this.sniMatchers);
    }

    public void setSNIMatchers(Collection<BCSNIMatcher> matchers) {
        this.sniMatchers = copyList(matchers);
    }

    public String[] getApplicationProtocols() {
        return (String[]) this.applicationProtocols.clone();
    }

    public void setApplicationProtocols(String[] applicationProtocols2) {
        this.applicationProtocols = (String[]) applicationProtocols2.clone();
    }

    public BCApplicationProtocolSelector<SSLEngine> getEngineAPSelector() {
        return this.engineAPSelector;
    }

    public void setEngineAPSelector(BCApplicationProtocolSelector<SSLEngine> engineAPSelector2) {
        this.engineAPSelector = engineAPSelector2;
    }

    public BCApplicationProtocolSelector<SSLSocket> getSocketAPSelector() {
        return this.socketAPSelector;
    }

    public void setSocketAPSelector(BCApplicationProtocolSelector<SSLSocket> socketAPSelector2) {
        this.socketAPSelector = socketAPSelector2;
    }

    public ProvSSLSession getSessionToResume() {
        return this.sessionToResume;
    }

    public void setSessionToResume(ProvSSLSession sessionToResume2) {
        this.sessionToResume = sessionToResume2;
    }
}
