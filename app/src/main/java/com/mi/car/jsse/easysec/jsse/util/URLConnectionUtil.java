package com.mi.car.jsse.easysec.jsse.util;

import java.io.IOException;
import java.io.InputStream;
import java.net.Proxy;
import java.net.URL;
import java.net.URLConnection;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLSocketFactory;

public class URLConnectionUtil {
    protected final SSLSocketFactory sslSocketFactory;

    public URLConnectionUtil() {
        this(null);
    }

    public URLConnectionUtil(SSLSocketFactory sslSocketFactory2) {
        this.sslSocketFactory = sslSocketFactory2;
    }

    public URLConnection openConnection(URL url) throws IOException {
        return configureConnection(url, url.openConnection());
    }

    public URLConnection openConnection(URL url, Proxy proxy) throws IOException {
        return configureConnection(url, url.openConnection(proxy));
    }

    public InputStream openInputStream(URL url) throws IOException {
        return openConnection(url).getInputStream();
    }

    /* access modifiers changed from: protected */
    public URLConnection configureConnection(URL url, URLConnection connection) {
        if (!(connection instanceof HttpsURLConnection)) {
            return connection;
        }
        HttpsURLConnection https = (HttpsURLConnection) connection;
        SSLSocketFactory delegate = this.sslSocketFactory;
        if (delegate == null) {
            delegate = https.getSSLSocketFactory();
        }
        https.setSSLSocketFactory(createSSLSocketFactory(delegate, url));
        return https;
    }

    /* access modifiers changed from: protected */
    public SSLSocketFactory createSSLSocketFactory(SSLSocketFactory delegate, URL url) {
        return new SNISocketFactory(delegate, url);
    }
}
