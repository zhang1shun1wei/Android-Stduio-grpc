package com.mi.car.jsse.easysec.jsse.provider;

import com.mi.car.jsse.easysec.jsse.BCSNIServerName;
import java.util.List;
import javax.net.ssl.ExtendedSSLSession;

class ImportSSLSession_8 extends ImportSSLSession_7 {
    ImportSSLSession_8(ExtendedSSLSession sslSession) {
        super(sslSession);
    }

    @Override // com.mi.car.jsse.easysec.jsse.BCExtendedSSLSession, com.mi.car.jsse.easysec.jsse.provider.ImportSSLSession_7
    public List<BCSNIServerName> getRequestedServerNames() {
        return JsseUtils_8.importSNIServerNames(this.sslSession.getRequestedServerNames());
    }
}
