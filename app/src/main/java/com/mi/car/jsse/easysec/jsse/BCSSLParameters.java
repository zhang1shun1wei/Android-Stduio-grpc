package com.mi.car.jsse.easysec.jsse;

import com.mi.car.jsse.easysec.jsse.java.security.BCAlgorithmConstraints;
import com.mi.car.jsse.easysec.tls.TlsUtils;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

public final class BCSSLParameters {
    private BCAlgorithmConstraints algorithmConstraints;
    private String[] applicationProtocols = TlsUtils.EMPTY_STRINGS;
    private String[] cipherSuites;
    private String endpointIdentificationAlgorithm;
    private int maximumPacketSize = 0;
    private boolean needClientAuth;
    private String[] protocols;
    private List<BCSNIServerName> serverNames;
    private List<BCSNIMatcher> sniMatchers;
    private boolean useCipherSuitesOrder;
    private boolean wantClientAuth;

    private static <T> List<T> copyList(Collection<T> list) {
        if (list == null) {
            return null;
        }
        if (list.isEmpty()) {
            return Collections.emptyList();
        }
        return Collections.unmodifiableList(new ArrayList(list));
    }

    public BCSSLParameters() {
    }

    public BCSSLParameters(String[] cipherSuites2) {
        setCipherSuites(cipherSuites2);
    }

    public BCSSLParameters(String[] cipherSuites2, String[] protocols2) {
        setCipherSuites(cipherSuites2);
        setProtocols(protocols2);
    }

    public String[] getApplicationProtocols() {
        return TlsUtils.clone(this.applicationProtocols);
    }

    public void setApplicationProtocols(String[] applicationProtocols2) {
        if (applicationProtocols2 == null) {
            throw new NullPointerException("'applicationProtocols' cannot be null");
        }
        String[] check = TlsUtils.clone(applicationProtocols2);
        for (String entry : check) {
            if (TlsUtils.isNullOrEmpty(entry)) {
                throw new IllegalArgumentException("'applicationProtocols' entries cannot be null or empty strings");
            }
        }
        this.applicationProtocols = check;
    }

    public String[] getCipherSuites() {
        return TlsUtils.clone(this.cipherSuites);
    }

    public void setCipherSuites(String[] cipherSuites2) {
        this.cipherSuites = TlsUtils.clone(cipherSuites2);
    }

    public String[] getProtocols() {
        return TlsUtils.clone(this.protocols);
    }

    public void setProtocols(String[] protocols2) {
        this.protocols = TlsUtils.clone(protocols2);
    }

    public boolean getWantClientAuth() {
        return this.wantClientAuth;
    }

    public void setWantClientAuth(boolean wantClientAuth2) {
        this.wantClientAuth = wantClientAuth2;
        this.needClientAuth = false;
    }

    public boolean getNeedClientAuth() {
        return this.needClientAuth;
    }

    public void setNeedClientAuth(boolean needClientAuth2) {
        this.needClientAuth = needClientAuth2;
        this.wantClientAuth = false;
    }

    public String getEndpointIdentificationAlgorithm() {
        return this.endpointIdentificationAlgorithm;
    }

    public void setEndpointIdentificationAlgorithm(String endpointIdentificationAlgorithm2) {
        this.endpointIdentificationAlgorithm = endpointIdentificationAlgorithm2;
    }

    public BCAlgorithmConstraints getAlgorithmConstraints() {
        return this.algorithmConstraints;
    }

    public void setAlgorithmConstraints(BCAlgorithmConstraints algorithmConstraints2) {
        this.algorithmConstraints = algorithmConstraints2;
    }

    public void setServerNames(List<BCSNIServerName> serverNames2) {
        if (serverNames2 == null) {
            this.serverNames = null;
            return;
        }
        List<BCSNIServerName> copy = copyList(serverNames2);
        Set<Integer> types = new HashSet<>();
        for (BCSNIServerName serverName : copy) {
            int type = serverName.getType();
            if (!types.add(Integer.valueOf(type))) {
                throw new IllegalArgumentException("Found duplicate SNI server name entry of type " + type);
            }
        }
        this.serverNames = copy;
    }

    public List<BCSNIServerName> getServerNames() {
        return copyList(this.serverNames);
    }

    public void setSNIMatchers(Collection<BCSNIMatcher> sniMatchers2) {
        if (sniMatchers2 == null) {
            this.sniMatchers = null;
            return;
        }
        List<BCSNIMatcher> copy = copyList(sniMatchers2);
        Set<Integer> types = new HashSet<>();
        for (BCSNIMatcher sniMatcher : copy) {
            int type = sniMatcher.getType();
            if (!types.add(Integer.valueOf(type))) {
                throw new IllegalArgumentException("Found duplicate SNI matcher entry of type " + type);
            }
        }
        this.sniMatchers = copy;
    }

    public Collection<BCSNIMatcher> getSNIMatchers() {
        return copyList(this.sniMatchers);
    }

    public void setUseCipherSuitesOrder(boolean useCipherSuitesOrder2) {
        this.useCipherSuitesOrder = useCipherSuitesOrder2;
    }

    public boolean getUseCipherSuitesOrder() {
        return this.useCipherSuitesOrder;
    }

    public void setMaximumPacketSize(int maximumPacketSize2) {
        if (maximumPacketSize2 < 0) {
            throw new IllegalArgumentException("The maximum packet size cannot be negative");
        }
        this.maximumPacketSize = maximumPacketSize2;
    }

    public int getMaximumPacketSize() {
        return this.maximumPacketSize;
    }
}
