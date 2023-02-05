package com.mi.car.jsse.easysec.jsse.provider;

import com.mi.car.jsse.easysec.tls.TlsServerProtocol;
import java.io.Closeable;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

/* access modifiers changed from: package-private */
public class ProvTlsServerProtocol extends TlsServerProtocol {
    private final Closeable closeable;

    ProvTlsServerProtocol(InputStream input, OutputStream output, Closeable closeable2) {
        super(input, output);
        this.closeable = closeable2;
    }

    /* access modifiers changed from: protected */
    @Override // com.mi.car.jsse.easysec.tls.TlsProtocol
    public void closeConnection() throws IOException {
        this.closeable.close();
    }
}
