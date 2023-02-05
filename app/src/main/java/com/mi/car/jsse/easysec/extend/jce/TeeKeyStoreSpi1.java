package com.mi.car.jsse.easysec.extend.jce;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.UnsupportedEncodingException;
import java.security.Key;
import java.security.KeyStoreException;
import java.security.KeyStoreSpi;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Base64;
import java.util.Date;
import java.util.Enumeration;
import java.util.Hashtable;

import com.mi.car.jsse.easysec.GrpcClient;
import com.mi.car.jsse.easysec.extend.drive.TeeX509Native;

public class TeeKeyStoreSpi1 extends KeyStoreSpi {
    private final Hashtable<String, Object> entries = new Hashtable<>();

    @Override // java.security.KeyStoreSpi
    public Key engineGetKey(String alias, char[] password) throws NoSuchAlgorithmException, UnrecoverableKeyException {
        Object obj = this.entries.get(alias);
        if (obj instanceof KeyEntry) {
            return ((KeyEntry) obj).privKey;
        }
        return null;
    }

    public Certificate[] engineGetCertificateChain(String alias) {
        Object obj = this.entries.get(alias);
        if (obj instanceof KeyEntry) {
            return (Certificate[]) ((KeyEntry) obj).chain.clone();
        }
        return null;
    }

    public Certificate engineGetCertificate(String alias) {
        Object obj = this.entries.get(alias);
        if (obj instanceof KeyEntry) {
            if (((KeyEntry) obj).chain != null) {
                return ((KeyEntry) obj).chain[0];
            }
            return null;
        } else if (obj instanceof TrustEntry) {
            return ((TrustEntry) obj).cert;
        } else {
            return null;
        }
    }

    public Date engineGetCreationDate(String alias) {
        Object obj = this.entries.get(alias);
        if (obj instanceof KeyEntry) {
            return new Date(((KeyEntry) obj).date.getTime());
        }
        if (obj instanceof TrustEntry) {
            return new Date(((TrustEntry) obj).date.getTime());
        }
        return null;
    }

    @Override // java.security.KeyStoreSpi
    public void engineSetKeyEntry(String alias, Key key, char[] password, Certificate[] chain) throws KeyStoreException {
        throw new KeyStoreException("unsupported set key");
    }

    @Override // java.security.KeyStoreSpi
    public void engineSetKeyEntry(String alias, byte[] key, Certificate[] chain) throws KeyStoreException {
        throw new KeyStoreException("unsupported set key");
    }

    @Override // java.security.KeyStoreSpi
    public void engineSetCertificateEntry(String alias, Certificate cert) throws KeyStoreException {
        throw new KeyStoreException("unsupported set");
    }

    @Override // java.security.KeyStoreSpi
    public void engineDeleteEntry(String alias) throws KeyStoreException {
        throw new KeyStoreException("unsupported delete");
    }

    @Override // java.security.KeyStoreSpi
    public Enumeration<String> engineAliases() {
        return this.entries.keys();
    }

    public boolean engineContainsAlias(String alias) {
        return this.entries.contains(alias);
    }

    public int engineSize() {
        return this.entries.size();
    }

    public boolean engineIsKeyEntry(String alias) {
        return this.entries.get(alias) instanceof KeyEntry;
    }

    public boolean engineIsCertificateEntry(String alias) {
        return this.entries.get(alias) instanceof TrustEntry;
    }

    public String engineGetCertificateAlias(Certificate cert) {
        Enumeration<String> keys = this.entries.keys();
        while (keys.hasMoreElements()) {
            String alias = keys.nextElement();
            Object obj = this.entries.get(alias);
            if (obj instanceof KeyEntry) {
                for (Certificate certificate : ((KeyEntry) obj).chain) {
                    if (certificate.equals(cert)) {
                        return alias;
                    }
                }
                continue;
            } else if ((obj instanceof TrustEntry) && cert.equals(((TrustEntry) obj).cert)) {
                return alias;
            }
        }
        return null;
    }

    @Override // java.security.KeyStoreSpi
    public void engineStore(OutputStream stream, char[] password) throws IOException, NoSuchAlgorithmException, CertificateException {
        throw new IOException("unsupported store");
    }

    @Override // java.security.KeyStoreSpi
    public void engineLoad(InputStream stream, char[] password) throws IOException, NoSuchAlgorithmException, CertificateException {
        CertificateFactory certfactory = CertificateFactory.getInstance("X.509");
        if (stream instanceof KeyStoreInputStream) {
            String cert = GrpcClient.getSingleton().getIdentityCert();
//            String cert = TeeX509Native.getIdentityCertJNI();
            if (cert == null || cert.length() == 0) {
                throw new IllegalArgumentException("调用jni身份证书接口返回错误");
            }
            if(cert.length() <= 20) {
                throw new IllegalArgumentException(cert);
            }
            Certificate certificate = certfactory.generateCertificate(new ByteArrayInputStream(Base64.getMimeDecoder().decode(cert.replaceAll("-----BEGIN CERTIFICATE-----", "").replaceAll("-----END CERTIFICATE-----", "").replaceAll("\n", ""))));
            this.entries.put(((X509Certificate) certificate).getSubjectDN().getName(), new KeyEntry(new Date(), new TeeEcPrivateKey(), new Certificate[]{certificate}));
        } else if (stream instanceof TrustStoreInputStream) {
            String certs = GrpcClient.getSingleton().getX509CertChain();
//            String certs = TeeX509Native.getX509CertChainJNI();
            if (certs == null || certs.length() == 0) {
                throw new IllegalArgumentException("调用jni身份证书接口返回错误");
            }
            if(certs.length() <= 20) {
                throw new IllegalArgumentException(certs);
            }
            for (String str : certs.split("-----END CERTIFICATE-----\n-----BEGIN CERTIFICATE-----")) {
                Certificate certificate2 = certfactory.generateCertificate(new ByteArrayInputStream(Base64.getMimeDecoder().decode(str.replaceAll("-----BEGIN CERTIFICATE-----", "").replaceAll("-----END CERTIFICATE-----", "").replaceAll("\n", ""))));
                this.entries.put(((X509Certificate) certificate2).getSubjectDN().getName(), new TrustEntry(new Date(), certificate2));
            }
        } else {
            throw new UnsupportedEncodingException("unsupported type");
        }
    }

    private static class KeyEntry {
        Certificate[] chain;
        Date date;
        Key privKey;

        public String toString() {
            return "TeeKeyStoreSpi.KeyEntry(date=" + this.date + ", privKey=" + this.privKey + ", chain=" + Arrays.deepToString(this.chain) + ")";
        }

        public KeyEntry(Date date2, Key privKey2, Certificate[] chain2) {
            this.date = date2;
            this.privKey = privKey2;
            this.chain = chain2;
        }
    }

    private static class TrustEntry {
        Certificate cert;
        Date date;

        public String toString() {
            return "TeeKeyStoreSpi.TrustEntry(date=" + this.date + ", cert=" + this.cert + ")";
        }

        public TrustEntry(Date date2, Certificate cert2) {
            this.date = date2;
            this.cert = cert2;
        }
    }
}
