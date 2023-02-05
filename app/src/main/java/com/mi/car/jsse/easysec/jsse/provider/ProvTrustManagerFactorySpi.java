package com.mi.car.jsse.easysec.jsse.provider;

import com.mi.car.jsse.easysec.jcajce.util.JcaJceHelper;
import com.mi.car.jsse.easysec.tls.TlsUtils;
import java.io.BufferedInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchProviderException;
import java.security.cert.CertPathParameters;
import java.security.cert.Certificate;
import java.security.cert.PKIXParameters;
import java.security.cert.TrustAnchor;
import java.security.cert.X509Certificate;
import java.util.Collections;
import java.util.Enumeration;
import java.util.HashSet;
import java.util.Set;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.net.ssl.CertPathTrustManagerParameters;
import javax.net.ssl.ManagerFactoryParameters;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactorySpi;

/* access modifiers changed from: package-private */
public class ProvTrustManagerFactorySpi extends TrustManagerFactorySpi {
    private static final Logger LOG = Logger.getLogger(ProvTrustManagerFactorySpi.class.getName());
    private static final boolean provKeyStoreTypeCompat = PropertyUtils.getBooleanSecurityProperty("keystore.type.compat", false);
    protected final JcaJceHelper helper;
    protected final boolean isInFipsMode;
    protected ProvX509TrustManager x509TrustManager;

    static KeyStore getDefaultTrustStore() throws Exception {
        String defaultType = KeyStore.getDefaultType();
        boolean defaultCacertsToJKS = provKeyStoreTypeCompat && "pkcs12".equalsIgnoreCase(defaultType);
        String tsPath = null;
        char[] tsPassword = null;
        String tsPathProp = PropertyUtils.getStringSystemProperty("javax.net.ssl.trustStore");
        if (!"NONE".equals(tsPathProp)) {
            if (tsPathProp == null) {
                String javaHome = PropertyUtils.getStringSystemProperty("java.home");
                if (javaHome != null) {
                    String jsseCacertsPath = javaHome + "/lib/security/jssecacerts".replace("/", File.separator);
                    if (new File(jsseCacertsPath).exists()) {
                        if (defaultCacertsToJKS) {
                            defaultType = "jks";
                        }
                        tsPath = jsseCacertsPath;
                    } else {
                        String cacertsPath = javaHome + "/lib/security/cacerts".replace("/", File.separator);
                        if (new File(cacertsPath).exists()) {
                            if (defaultCacertsToJKS) {
                                defaultType = "jks";
                            }
                            tsPath = cacertsPath;
                        }
                    }
                }
            } else if (new File(tsPathProp).exists()) {
                tsPath = tsPathProp;
            }
        }
        KeyStore ks = createTrustStore(defaultType);
        String tsPasswordProp = PropertyUtils.getSensitiveStringSystemProperty("javax.net.ssl.trustStorePassword");
        if (tsPasswordProp != null) {
            tsPassword = tsPasswordProp.toCharArray();
        }
        InputStream tsInput = null;
        if (tsPath == null) {
            try {
                LOG.config("Initializing default trust store as empty");
            } catch (Throwable th) {
                if (0 != 0) {
                    tsInput.close();
                }
                throw th;
            }
        } else {
            LOG.config("Initializing default trust store from path: " + tsPath);
            tsInput = new BufferedInputStream(new FileInputStream(tsPath));
        }
        try {
            ks.load(tsInput, tsPassword);
        } catch (NullPointerException e) {
            ks = KeyStore.getInstance("BCFKS");
            ks.load(null, null);
        }
        if (tsInput != null) {
            tsInput.close();
        }
        return ks;
    }

    ProvTrustManagerFactorySpi(boolean isInFipsMode2, JcaJceHelper helper2) {
        this.isInFipsMode = isInFipsMode2;
        this.helper = helper2;
    }

    /* access modifiers changed from: protected */
    public TrustManager[] engineGetTrustManagers() {
        if (this.x509TrustManager == null) {
            throw new IllegalStateException("TrustManagerFactory not initialized");
        }
        return new TrustManager[]{this.x509TrustManager.getExportX509TrustManager()};
    }

    /* access modifiers changed from: protected */
    @Override // javax.net.ssl.TrustManagerFactorySpi
    public void engineInit(KeyStore ks) throws KeyStoreException {
        if (ks == null) {
            try {
                ks = getDefaultTrustStore();
            } catch (SecurityException e) {
                LOG.log(Level.WARNING, "Skipped default trust store", (Throwable) e);
            } catch (Error e2) {
                LOG.log(Level.WARNING, "Skipped default trust store", (Throwable) e2);
                throw e2;
            } catch (RuntimeException e3) {
                LOG.log(Level.WARNING, "Skipped default trust store", (Throwable) e3);
                throw e3;
            } catch (Exception e4) {
                LOG.log(Level.WARNING, "Skipped default trust store", (Throwable) e4);
                throw new KeyStoreException("Failed to load default trust store", e4);
            }
        }
        try {
            this.x509TrustManager = new ProvX509TrustManager(this.isInFipsMode, this.helper, getTrustAnchors(ks));
        } catch (InvalidAlgorithmParameterException e5) {
            throw new KeyStoreException("Failed to create trust manager", e5);
        }
    }

    /* access modifiers changed from: protected */
    @Override // javax.net.ssl.TrustManagerFactorySpi
    public void engineInit(ManagerFactoryParameters spec) throws InvalidAlgorithmParameterException {
        if (spec instanceof CertPathTrustManagerParameters) {
            CertPathParameters certPathParameters = ((CertPathTrustManagerParameters) spec).getParameters();
            if (!(certPathParameters instanceof PKIXParameters)) {
                throw new InvalidAlgorithmParameterException("parameters must inherit from PKIXParameters");
            }
            this.x509TrustManager = new ProvX509TrustManager(this.isInFipsMode, this.helper, (PKIXParameters) certPathParameters);
        } else if (spec == null) {
            throw new InvalidAlgorithmParameterException("spec cannot be null");
        } else {
            throw new InvalidAlgorithmParameterException("unknown spec: " + spec.getClass().getName());
        }
    }

    private static void collectTrustAnchor(Set<TrustAnchor> trustAnchors, Certificate certificate) {
        if (certificate instanceof X509Certificate) {
            trustAnchors.add(new TrustAnchor((X509Certificate) certificate, null));
        }
    }

    private static KeyStore createTrustStore(String defaultType) throws NoSuchProviderException, KeyStoreException {
        String tsType = getTrustStoreType(defaultType);
        String tsProv = PropertyUtils.getStringSystemProperty("javax.net.ssl.trustStoreProvider");
        if (TlsUtils.isNullOrEmpty(tsProv)) {
            return KeyStore.getInstance(tsType);
        }
        return KeyStore.getInstance(tsType, tsProv);
    }

    private static Set<TrustAnchor> getTrustAnchors(KeyStore trustStore) throws KeyStoreException {
        Certificate[] chain;
        if (trustStore == null) {
            return Collections.emptySet();
        }
        Set<TrustAnchor> trustAnchors = new HashSet<>();
        Enumeration<String> en = trustStore.aliases();
        while (en.hasMoreElements()) {
            String alias = en.nextElement();
            if (trustStore.isCertificateEntry(alias)) {
                collectTrustAnchor(trustAnchors, trustStore.getCertificate(alias));
            } else if (trustStore.isKeyEntry(alias) && (chain = trustStore.getCertificateChain(alias)) != null && chain.length > 0) {
                collectTrustAnchor(trustAnchors, chain[0]);
            }
        }
        return trustAnchors;
    }

    private static String getTrustStoreType(String defaultType) {
        String tsType = PropertyUtils.getStringSystemProperty("javax.net.ssl.trustStoreType");
        return tsType == null ? defaultType : tsType;
    }
}
