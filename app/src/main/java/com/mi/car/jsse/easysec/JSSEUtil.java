package com.mi.car.jsse.easysec;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.URL;
import java.security.KeyStore;
import java.security.Security;

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManagerFactory;

import com.mi.car.jsse.easysec.extend.jce.KeyStoreInputStream;
import com.mi.car.jsse.easysec.extend.jce.TrustStoreInputStream;
import com.mi.car.jsse.easysec.jce.provider.EasysecProvider;
import com.mi.car.jsse.easysec.jsse.provider.EasysecJsseProvider;


public class JSSEUtil {
    public static SSLContext makeSSLContext() {
        try {
            Security.addProvider(new EasysecProvider());
            Security.addProvider(new EasysecJsseProvider());
            KeyStore store = KeyStore.getInstance("TEEKS", EasysecJsseProvider.PROVIDER_NAME);
            store.load(new KeyStoreInputStream(), null);
            store.load(new TrustStoreInputStream(), null);
            KeyManagerFactory kmf = KeyManagerFactory.getInstance("X509", EasysecJsseProvider.PROVIDER_NAME);
            kmf.init(store, null);
            TrustManagerFactory tmf = TrustManagerFactory.getInstance("X509", EasysecJsseProvider.PROVIDER_NAME);
            tmf.init(store);

            //取得SSL的SSLContext实例
            SSLContext sc = SSLContext.getInstance("TLS", EasysecJsseProvider.PROVIDER_NAME);
            sc.init(kmf.getKeyManagers(), tmf.getTrustManagers(), null);
            return sc;
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

}

