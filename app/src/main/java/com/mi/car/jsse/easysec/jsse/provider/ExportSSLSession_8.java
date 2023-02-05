package com.mi.car.jsse.easysec.jsse.provider;

import com.mi.car.jsse.easysec.jsse.BCExtendedSSLSession;
import java.util.List;
import javax.net.ssl.SNIServerName;

class ExportSSLSession_8 extends ExportSSLSession_7 {
    ExportSSLSession_8(BCExtendedSSLSession sslSession) {
        super(sslSession);
    }

    @Override // javax.net.ssl.ExtendedSSLSession
    public List<SNIServerName> getRequestedServerNames() {
        return JsseUtils_8.exportSNIServerNames(this.sslSession.getRequestedServerNames());
    }
}
