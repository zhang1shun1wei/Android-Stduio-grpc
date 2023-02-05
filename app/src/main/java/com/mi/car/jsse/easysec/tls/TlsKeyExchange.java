package com.mi.car.jsse.easysec.tls;

import com.mi.car.jsse.easysec.tls.crypto.TlsSecret;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

public interface TlsKeyExchange {
    void generateClientKeyExchange(OutputStream outputStream) throws IOException;

    TlsSecret generatePreMasterSecret() throws IOException;

    byte[] generateServerKeyExchange() throws IOException;

    short[] getClientCertificateTypes();

    void init(TlsContext tlsContext);

    void processClientCertificate(Certificate certificate) throws IOException;

    void processClientCredentials(TlsCredentials tlsCredentials) throws IOException;

    void processClientKeyExchange(InputStream inputStream) throws IOException;

    void processServerCertificate(Certificate certificate) throws IOException;

    void processServerCredentials(TlsCredentials tlsCredentials) throws IOException;

    void processServerKeyExchange(InputStream inputStream) throws IOException;

    boolean requiresCertificateVerify();

    boolean requiresServerKeyExchange();

    void skipClientCredentials() throws IOException;

    void skipServerCredentials() throws IOException;

    void skipServerKeyExchange() throws IOException;
}
