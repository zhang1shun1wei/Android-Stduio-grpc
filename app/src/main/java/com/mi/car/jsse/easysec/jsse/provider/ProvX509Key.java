package com.mi.car.jsse.easysec.jsse.provider;

import com.mi.car.jsse.easysec.jsse.BCX509Key;
import com.mi.car.jsse.easysec.tls.TlsUtils;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.net.ssl.X509KeyManager;

class ProvX509Key implements BCX509Key {
    private static final Logger LOG = Logger.getLogger(ProvX509Key.class.getName());
    private final X509Certificate[] certificateChain;
    private final String keyType;
    private final PrivateKey privateKey;

    static ProvX509Key from(X509KeyManager x509KeyManager, String keyType2, String alias) {
        X509Certificate[] certificateChain2;
        PrivateKey privateKey2;
        if (x509KeyManager == null) {
            throw new NullPointerException("'x509KeyManager' cannot be null");
        } else if (keyType2 == null || alias == null || (certificateChain2 = getCertificateChain(x509KeyManager, alias)) == null || (privateKey2 = getPrivateKey(x509KeyManager, alias)) == null) {
            return null;
        } else {
            return new ProvX509Key(keyType2, privateKey2, certificateChain2);
        }
    }

    static ProvX509Key validate(X509KeyManager x509KeyManager, boolean forServer, String keyType2, String alias, TransportData transportData) {
        X509Certificate[] certificateChain2;
        if (x509KeyManager == null) {
            throw new NullPointerException("'x509KeyManager' cannot be null");
        } else if (keyType2 == null || alias == null || (certificateChain2 = getCertificateChain(x509KeyManager, alias)) == null) {
            return null;
        } else {
            if (ProvX509KeyManager.isSuitableKeyType(forServer, keyType2, certificateChain2[0], transportData)) {
                PrivateKey privateKey2 = getPrivateKey(x509KeyManager, alias);
                if (privateKey2 != null) {
                    return new ProvX509Key(keyType2, privateKey2, certificateChain2);
                }
                return null;
            } else if (!LOG.isLoggable(Level.FINER)) {
                return null;
            } else {
                LOG.finer("Rejecting alias '" + alias + "': not suitable for key type '" + keyType2 + "'");
                return null;
            }
        }
    }

    private static X509Certificate[] getCertificateChain(X509KeyManager x509KeyManager, String alias) {
        X509Certificate[] certificateChain2 = x509KeyManager.getCertificateChain(alias);
        if (TlsUtils.isNullOrEmpty(certificateChain2)) {
            LOG.finer("Rejecting alias '" + alias + "': no certificate chain");
            return null;
        }
        X509Certificate[] certificateChain3 = (X509Certificate[]) certificateChain2.clone();
        if (!JsseUtils.containsNull(certificateChain3)) {
            return certificateChain3;
        }
        LOG.finer("Rejecting alias '" + alias + "': invalid certificate chain");
        return null;
    }

    private static PrivateKey getPrivateKey(X509KeyManager x509KeyManager, String alias) {
        PrivateKey privateKey2 = x509KeyManager.getPrivateKey(alias);
        if (privateKey2 != null) {
            return privateKey2;
        }
        LOG.finer("Rejecting alias '" + alias + "': no private key");
        return null;
    }

    ProvX509Key(String keyType2, PrivateKey privateKey2, X509Certificate[] certificateChain2) {
        this.keyType = keyType2;
        this.privateKey = privateKey2;
        this.certificateChain = certificateChain2;
    }

    @Override // com.mi.car.jsse.easysec.jsse.BCX509Key
    public X509Certificate[] getCertificateChain() {
        return (X509Certificate[]) this.certificateChain.clone();
    }

    @Override // com.mi.car.jsse.easysec.jsse.BCX509Key
    public String getKeyType() {
        return this.keyType;
    }

    @Override // com.mi.car.jsse.easysec.jsse.BCX509Key
    public PrivateKey getPrivateKey() {
        return this.privateKey;
    }
}
