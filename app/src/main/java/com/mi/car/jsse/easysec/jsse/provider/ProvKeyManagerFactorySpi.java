package com.mi.car.jsse.easysec.jsse.provider;

import com.mi.car.jsse.easysec.jcajce.util.JcaJceHelper;
import com.mi.car.jsse.easysec.jsse.BCX509ExtendedKeyManager;
import com.mi.car.jsse.easysec.tls.TlsUtils;
import java.io.BufferedInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.UnrecoverableKeyException;
import java.util.logging.Logger;
import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactorySpi;
import javax.net.ssl.KeyStoreBuilderParameters;
import javax.net.ssl.ManagerFactoryParameters;

/* access modifiers changed from: package-private */
public class ProvKeyManagerFactorySpi extends KeyManagerFactorySpi {
    private static final Logger LOG = Logger.getLogger(ProvKeyManagerFactorySpi.class.getName());
    protected final JcaJceHelper helper;
    protected final boolean isInFipsMode;
    protected BCX509ExtendedKeyManager x509KeyManager;

    static KeyStoreConfig getDefaultKeyStore() throws Exception {
        String defaultType = KeyStore.getDefaultType();
        String ksPath = null;
        char[] ksPassword = null;
        String ksPathProp = PropertyUtils.getStringSystemProperty("javax.net.ssl.keyStore");
        if (!"NONE".equals(ksPathProp) && ksPathProp != null && new File(ksPathProp).exists()) {
            ksPath = ksPathProp;
        }
        KeyStore ks = createKeyStore(defaultType);
        String ksPasswordProp = PropertyUtils.getSensitiveStringSystemProperty("javax.net.ssl.keyStorePassword");
        if (ksPasswordProp != null) {
            ksPassword = ksPasswordProp.toCharArray();
        }
        InputStream ksInput = null;
        if (ksPath == null) {
            try {
                LOG.config("Initializing default key store as empty");
            } catch (Throwable th) {
                if (0 != 0) {
                    ksInput.close();
                }
                throw th;
            }
        } else {
            LOG.config("Initializing default key store from path: " + ksPath);
            ksInput = new BufferedInputStream(new FileInputStream(ksPath));
        }
        try {
            ks.load(ksInput, ksPassword);
        } catch (NullPointerException e) {
            ks = KeyStore.getInstance("BCFKS");
            ks.load(null, null);
        }
        if (ksInput != null) {
            ksInput.close();
        }
        return new KeyStoreConfig(ks, ksPassword);
    }

    ProvKeyManagerFactorySpi(boolean isInFipsMode2, JcaJceHelper helper2) {
        this.isInFipsMode = isInFipsMode2;
        this.helper = helper2;
    }

    /* access modifiers changed from: protected */
    public KeyManager[] engineGetKeyManagers() {
        if (this.x509KeyManager == null) {
            throw new IllegalStateException("KeyManagerFactory not initialized");
        }
        return new KeyManager[]{this.x509KeyManager};
    }

    /* access modifiers changed from: protected */
    @Override // javax.net.ssl.KeyManagerFactorySpi
    public void engineInit(KeyStore ks, char[] ksPassword) throws KeyStoreException, NoSuchAlgorithmException, UnrecoverableKeyException {
        this.x509KeyManager = new ProvX509KeyManagerSimple(this.isInFipsMode, this.helper, ks, ksPassword);
    }

    /* access modifiers changed from: protected */
    @Override // javax.net.ssl.KeyManagerFactorySpi
    public void engineInit(ManagerFactoryParameters managerFactoryParameters) throws InvalidAlgorithmParameterException {
        if (managerFactoryParameters instanceof KeyStoreBuilderParameters) {
            this.x509KeyManager = new ProvX509KeyManager(this.isInFipsMode, this.helper, ((KeyStoreBuilderParameters) managerFactoryParameters).getParameters());
            return;
        }
        throw new InvalidAlgorithmParameterException("Parameters must be instance of KeyStoreBuilderParameters");
    }

    private static KeyStore createKeyStore(String defaultType) throws NoSuchProviderException, KeyStoreException {
        String ksType = getKeyStoreType(defaultType);
        String ksProv = PropertyUtils.getStringSystemProperty("javax.net.ssl.keyStoreProvider");
        if (TlsUtils.isNullOrEmpty(ksProv)) {
            return KeyStore.getInstance(ksType);
        }
        return KeyStore.getInstance(ksType, ksProv);
    }

    private static String getKeyStoreType(String defaultType) {
        String ksType = PropertyUtils.getStringSystemProperty("javax.net.ssl.keyStoreType");
        return ksType == null ? defaultType : ksType;
    }
}
