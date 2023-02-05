package com.mi.car.jsse.easysec.jsse.provider;

import com.mi.car.jsse.easysec.jsse.BCSNIServerName;

/* access modifiers changed from: package-private */
public class JsseSessionParameters {
    private final String endpointIDAlgorithm;
    private final BCSNIServerName matchedSNIServerName;

    JsseSessionParameters(String endpointIDAlgorithm2, BCSNIServerName matchedSNIServerName2) {
        this.endpointIDAlgorithm = endpointIDAlgorithm2;
        this.matchedSNIServerName = matchedSNIServerName2;
    }

    public String getEndpointIDAlgorithm() {
        return this.endpointIDAlgorithm;
    }

    public BCSNIServerName getMatchedSNIServerName() {
        return this.matchedSNIServerName;
    }
}
