package com.mi.car.jsse.easysec.jce.provider;

import com.mi.car.jsse.easysec.asn1.x500.X500Name;
import com.mi.car.jsse.easysec.asn1.x500.X500NameStyle;
import com.mi.car.jsse.easysec.jcajce.interfaces.BCX509Certificate;
import com.mi.car.jsse.easysec.x509.X509AttributeCertificate;
import java.security.cert.TrustAnchor;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import javax.security.auth.x500.X500Principal;

class PrincipalUtils {
    PrincipalUtils() {
    }

    static X500Name getCA(TrustAnchor trustAnchor) {
        return getX500Name(notNull(trustAnchor).getCA());
    }

    static X500Name getEncodedIssuerPrincipal(Object cert) {
        if (cert instanceof X509Certificate) {
            return getIssuerPrincipal((X509Certificate) cert);
        }
        return getX500Name((X500Principal) ((X509AttributeCertificate) cert).getIssuer().getPrincipals()[0]);
    }

    static X500Name getIssuerPrincipal(X509Certificate certificate) {
        if (certificate instanceof BCX509Certificate) {
            return notNull(((BCX509Certificate) certificate).getIssuerX500Name());
        }
        return getX500Name(notNull(certificate).getIssuerX500Principal());
    }

    static X500Name getIssuerPrincipal(X509CRL crl) {
        return getX500Name(notNull(crl).getIssuerX500Principal());
    }

    static X500Name getSubjectPrincipal(X509Certificate certificate) {
        if (certificate instanceof BCX509Certificate) {
            return notNull(((BCX509Certificate) certificate).getSubjectX500Name());
        }
        return getX500Name(notNull(certificate).getSubjectX500Principal());
    }

    static X500Name getX500Name(X500Principal principal) {
        return notNull(X500Name.getInstance(getEncoded(principal)));
    }

    static X500Name getX500Name(X500NameStyle style, X500Principal principal) {
        return notNull(X500Name.getInstance(style, getEncoded(principal)));
    }

    private static byte[] getEncoded(X500Principal principal) {
        return notNull(notNull(principal).getEncoded());
    }

    private static byte[] notNull(byte[] encoding) {
        if (encoding != null) {
            return encoding;
        }
        throw new IllegalStateException();
    }

    private static TrustAnchor notNull(TrustAnchor trustAnchor) {
        if (trustAnchor != null) {
            return trustAnchor;
        }
        throw new IllegalStateException();
    }

    private static X509Certificate notNull(X509Certificate certificate) {
        if (certificate != null) {
            return certificate;
        }
        throw new IllegalStateException();
    }

    private static X509CRL notNull(X509CRL crl) {
        if (crl != null) {
            return crl;
        }
        throw new IllegalStateException();
    }

    private static X500Name notNull(X500Name name) {
        if (name != null) {
            return name;
        }
        throw new IllegalStateException();
    }

    private static X500Principal notNull(X500Principal principal) {
        if (principal != null) {
            return principal;
        }
        throw new IllegalStateException();
    }
}
