package com.mi.car.jsse.easysec.jsse.provider;

import com.mi.car.jsse.easysec.tls.crypto.impl.jcajce.JcaTlsCryptoProvider;
import java.security.KeyManagementException;
import java.security.SecureRandom;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.net.ssl.KeyManager;
import javax.net.ssl.TrustManager;

/* access modifiers changed from: package-private */
public class DefaultSSLContextSpi extends ProvSSLContextSpi {
    private static final Logger LOG = Logger.getLogger(DefaultSSLContextSpi.class.getName());

    /* access modifiers changed from: private */
    public static Exception avoidCapturingException(Exception e) {
        return new KeyManagementException(e.getMessage());
    }

    private static class LazyInstance {
        private static final Exception initException;
        private static final DefaultSSLContextSpi instance;

        private LazyInstance() {
        }

        static {
            Exception ex = LazyManagers.initException;
            DefaultSSLContextSpi i = null;
            if (ex == null) {
                try {
                    i = new DefaultSSLContextSpi(false, new JcaTlsCryptoProvider());
                } catch (Exception e) {
                    DefaultSSLContextSpi.LOG.log(Level.WARNING, "Failed to load default SSLContext", (Throwable) e);
                    ex = DefaultSSLContextSpi.avoidCapturingException(e);
                }
            }
            initException = ex;
            instance = i;
        }
    }

    private static class LazyManagers {
        private static final Exception initException;
        private static final KeyManager[] keyManagers;
        private static final TrustManager[] trustManagers;

        private LazyManagers() {
        }

        static {
            Exception ex = null;
            KeyManager[] kms = null;
            TrustManager[] tms = null;
            try {
                tms = ProvSSLContextSpi.getDefaultTrustManagers();
            } catch (Exception e) {
                DefaultSSLContextSpi.LOG.log(Level.WARNING, "Failed to load default trust managers", (Throwable) e);
                ex = e;
            }
            if (ex == null) {
                try {
                    kms = ProvSSLContextSpi.getDefaultKeyManagers();
                } catch (Exception e2) {
                    DefaultSSLContextSpi.LOG.log(Level.WARNING, "Failed to load default key managers", (Throwable) e2);
                    ex = e2;
                }
            }
            if (ex != null) {
                ex = DefaultSSLContextSpi.avoidCapturingException(ex);
                kms = null;
                tms = null;
            }
            initException = ex;
            keyManagers = kms;
            trustManagers = tms;
        }
    }

    static ProvSSLContextSpi getDefaultInstance() throws Exception {
        if (LazyInstance.initException == null) {
            return LazyInstance.instance;
        }
        throw LazyInstance.initException;
    }

    DefaultSSLContextSpi(boolean isInFipsMode, JcaTlsCryptoProvider cryptoProvider) throws KeyManagementException {
        super(isInFipsMode, cryptoProvider, null);
        if (LazyManagers.initException != null) {
            throw new KeyManagementException("Default key/trust managers unavailable", LazyManagers.initException);
        }
        super.engineInit(LazyManagers.keyManagers, LazyManagers.trustManagers, null);
    }

    /* access modifiers changed from: protected */
    @Override // com.mi.car.jsse.easysec.jsse.provider.ProvSSLContextSpi, javax.net.ssl.SSLContextSpi
    public void engineInit(KeyManager[] kms, TrustManager[] tms, SecureRandom sr) throws KeyManagementException {
        throw new KeyManagementException("Default SSLContext is initialized automatically");
    }
}
