package com.mi.car.jsse.easysec.jsse.provider;

import com.mi.car.jsse.easysec.jsse.BCExtendedSSLSession;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Principal;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.cert.Certificate;
import java.security.cert.CertificateParsingException;
import java.util.Date;
import javax.net.ssl.SSLPeerUnverifiedException;
import javax.security.cert.CertificateEncodingException;
import javax.security.cert.CertificateException;
import javax.security.cert.CertificateExpiredException;
import javax.security.cert.CertificateNotYetValidException;
import javax.security.cert.X509Certificate;

class OldCertUtil {
    OldCertUtil() {
    }

    static X509Certificate[] getPeerCertificateChain(BCExtendedSSLSession sslSession) throws SSLPeerUnverifiedException {
        int count;
        boolean isFips = sslSession.isFipsMode();
        Certificate[] peerCertificates = sslSession.getPeerCertificates();
        X509Certificate[] result = new X509Certificate[peerCertificates.length];
        int i = 0;
        int count2 = 0;
        while (i < peerCertificates.length) {
            try {
                Certificate peerCertificate = peerCertificates[i];
                if (peerCertificate instanceof java.security.cert.X509Certificate) {
                    java.security.cert.X509Certificate peerX509Certificate = (java.security.cert.X509Certificate) peerCertificate;
                    if (isFips) {
                        count = count2 + 1;
                        try {
                            result[count2] = new X509CertificateWrapper(peerX509Certificate);
                        } catch (Exception e) {
                            e = e;
                            throw new SSLPeerUnverifiedException(e.getMessage());
                        }
                    } else {
                        count = count2 + 1;
                        result[count2] = X509Certificate.getInstance(peerX509Certificate.getEncoded());
                    }
                } else {
                    count = count2;
                }
                i++;
                count2 = count;
            } catch (Exception e2) {
                throw new SSLPeerUnverifiedException(e2.getMessage());
            }
        }
        if (count2 >= result.length) {
            return result;
        }
        X509Certificate[] tmp = new X509Certificate[count2];
        System.arraycopy(result, 0, tmp, 0, count2);
        return tmp;
    }

    private static class X509CertificateWrapper extends X509Certificate {
        private final java.security.cert.X509Certificate c;

        private X509CertificateWrapper(java.security.cert.X509Certificate c2) {
            this.c = c2;
        }

        @Override // javax.security.cert.X509Certificate
        public void checkValidity() throws CertificateExpiredException, CertificateNotYetValidException {
            try {
                this.c.checkValidity();
            } catch (java.security.cert.CertificateExpiredException e) {
                throw new CertificateExpiredException(e.getMessage());
            } catch (java.security.cert.CertificateNotYetValidException e2) {
                throw new CertificateNotYetValidException(e2.getMessage());
            }
        }

        @Override // javax.security.cert.X509Certificate
        public void checkValidity(Date date) throws CertificateExpiredException, CertificateNotYetValidException {
            try {
                this.c.checkValidity(date);
            } catch (java.security.cert.CertificateExpiredException e) {
                throw new CertificateExpiredException(e.getMessage());
            } catch (java.security.cert.CertificateNotYetValidException e2) {
                throw new CertificateNotYetValidException(e2.getMessage());
            }
        }

        public int getVersion() {
            return this.c.getVersion() - 1;
        }

        public BigInteger getSerialNumber() {
            return this.c.getSerialNumber();
        }

        public Principal getIssuerDN() {
            return this.c.getIssuerX500Principal();
        }

        public Principal getSubjectDN() {
            return this.c.getSubjectX500Principal();
        }

        public Date getNotBefore() {
            return this.c.getNotBefore();
        }

        public Date getNotAfter() {
            return this.c.getNotAfter();
        }

        public String getSigAlgName() {
            return this.c.getSigAlgName();
        }

        public String getSigAlgOID() {
            return this.c.getSigAlgOID();
        }

        public byte[] getSigAlgParams() {
            return this.c.getSigAlgParams();
        }

        @Override // javax.security.cert.Certificate
        public byte[] getEncoded() throws CertificateEncodingException {
            try {
                return this.c.getEncoded();
            } catch (java.security.cert.CertificateEncodingException e) {
                throw new CertificateEncodingException(e.getMessage());
            }
        }

        @Override // javax.security.cert.Certificate
        public void verify(PublicKey key) throws CertificateException, NoSuchAlgorithmException, InvalidKeyException, NoSuchProviderException, SignatureException {
            try {
                this.c.verify(key);
            } catch (java.security.cert.CertificateEncodingException e) {
                throw new CertificateEncodingException(e.getMessage());
            } catch (java.security.cert.CertificateExpiredException e2) {
                throw new CertificateExpiredException(e2.getMessage());
            } catch (java.security.cert.CertificateNotYetValidException e3) {
                throw new CertificateNotYetValidException(e3.getMessage());
            } catch (CertificateParsingException e4) {
                throw new javax.security.cert.CertificateParsingException(e4.getMessage());
            } catch (java.security.cert.CertificateException e5) {
                throw new CertificateException(e5.getMessage());
            }
        }

        @Override // javax.security.cert.Certificate
        public void verify(PublicKey key, String sigProvider) throws CertificateException, NoSuchAlgorithmException, InvalidKeyException, NoSuchProviderException, SignatureException {
            try {
                this.c.verify(key, sigProvider);
            } catch (java.security.cert.CertificateEncodingException e) {
                throw new CertificateEncodingException(e.getMessage());
            } catch (java.security.cert.CertificateExpiredException e2) {
                throw new CertificateExpiredException(e2.getMessage());
            } catch (java.security.cert.CertificateNotYetValidException e3) {
                throw new CertificateNotYetValidException(e3.getMessage());
            } catch (CertificateParsingException e4) {
                throw new javax.security.cert.CertificateParsingException(e4.getMessage());
            } catch (java.security.cert.CertificateException e5) {
                throw new CertificateException(e5.getMessage());
            }
        }

        public String toString() {
            return this.c.toString();
        }

        public PublicKey getPublicKey() {
            return this.c.getPublicKey();
        }
    }
}
