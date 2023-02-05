package com.mi.car.jsse.easysec.jsse.provider;

import com.mi.car.jsse.easysec.jsse.provider.NamedGroupInfo;
import java.security.Principal;
import java.util.List;

class JsseSecurityParameters {
    List<SignatureSchemeInfo> localSigSchemes;
    List<SignatureSchemeInfo> localSigSchemesCert;
    NamedGroupInfo.PerConnection namedGroups;
    List<SignatureSchemeInfo> peerSigSchemes;
    List<SignatureSchemeInfo> peerSigSchemesCert;
    List<byte[]> statusResponses;
    Principal[] trustedIssuers;

    JsseSecurityParameters() {
    }

    /* access modifiers changed from: package-private */
    public void clear() {
        this.namedGroups = null;
        this.localSigSchemes = null;
        this.localSigSchemesCert = null;
        this.peerSigSchemes = null;
        this.peerSigSchemesCert = null;
        this.statusResponses = null;
        this.trustedIssuers = null;
    }
}
