package com.mi.car.jsse.easysec.jsse.provider;

import com.mi.car.jsse.easysec.tls.TlsClientProtocol;
import java.io.Closeable;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

/* access modifiers changed from: package-private */
public class ProvTlsClientProtocol extends TlsClientProtocol {
    private static final boolean provAcceptRenegotiation = PropertyUtils.getBooleanSystemProperty("com.mi.car.jsse.easysec.jsse.client.acceptRenegotiation", false);
    private final Closeable closeable;

    ProvTlsClientProtocol(InputStream input, OutputStream output, Closeable closeable2) {
        super(input, output);
        this.closeable = closeable2;
    }

    /* access modifiers changed from: protected */
    @Override // com.mi.car.jsse.easysec.tls.TlsProtocol
    public void closeConnection() throws IOException {
        this.closeable.close();
    }

    /* access modifiers changed from: protected */
    @Override // com.mi.car.jsse.easysec.tls.TlsProtocol
    public int getRenegotiationPolicy() {
        return provAcceptRenegotiation ? 2 : 0;
    }
}
