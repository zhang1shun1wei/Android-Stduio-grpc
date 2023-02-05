package com.mi.car.jsse.easysec.jsse.provider;

import com.mi.car.jsse.easysec.asn1.ASN1Primitive;
import com.mi.car.jsse.easysec.asn1.ASN1String;
import com.mi.car.jsse.easysec.asn1.x500.AttributeTypeAndValue;
import com.mi.car.jsse.easysec.asn1.x500.RDN;
import com.mi.car.jsse.easysec.asn1.x500.X500Name;
import com.mi.car.jsse.easysec.asn1.x500.style.BCStyle;
import com.mi.car.jsse.easysec.jsse.BCSNIHostName;
import com.mi.car.jsse.easysec.util.IPAddress;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.List;
import java.util.Locale;
import java.util.StringTokenizer;
import javax.security.auth.x500.X500Principal;

class HostnameUtil {
    HostnameUtil() {
    }

    static void checkHostname(String hostname, X509Certificate certificate, boolean allWildcards) throws CertificateException {
        if (hostname == null) {
            throw new CertificateException("No hostname specified for HTTPS endpoint ID check");
        } else if (IPAddress.isValid(hostname)) {
            Collection<List<?>> subjectAltNames = certificate.getSubjectAlternativeNames();
            if (subjectAltNames != null) {
                for (List<?> subjectAltName : subjectAltNames) {
                    if (7 == ((Integer) subjectAltName.get(0)).intValue()) {
                        String ipAddress = (String) subjectAltName.get(1);
                        if (!hostname.equalsIgnoreCase(ipAddress)) {
                            try {
                                if (InetAddress.getByName(hostname).equals(InetAddress.getByName(ipAddress))) {
                                    return;
                                }
                            } catch (SecurityException | UnknownHostException e) {
                            }
                        } else {
                            return;
                        }
                    }
                }
            }
            throw new CertificateException("No subject alternative name found matching IP address " + hostname);
        } else if (isValidDomainName(hostname)) {
            Collection<List<?>> subjectAltNames2 = certificate.getSubjectAlternativeNames();
            if (subjectAltNames2 != null) {
                boolean foundAnyDNSNames = false;
                for (List<?> subjectAltName2 : subjectAltNames2) {
                    if (2 == ((Integer) subjectAltName2.get(0)).intValue()) {
                        foundAnyDNSNames = true;
                        if (matchesDNSName(hostname, (String) subjectAltName2.get(1), allWildcards)) {
                            return;
                        }
                    }
                }
                if (foundAnyDNSNames) {
                    throw new CertificateException("No subject alternative name found matching domain name " + hostname);
                }
            }
            ASN1Primitive commonName = findMostSpecificCN(certificate.getSubjectX500Principal());
            if (!(commonName instanceof ASN1String) || !matchesDNSName(hostname, ((ASN1String) commonName).getString(), allWildcards)) {
                throw new CertificateException("No name found matching " + hostname);
            }
        } else {
            throw new CertificateException("Invalid hostname specified for HTTPS endpoint ID check");
        }
    }

    private static ASN1Primitive findMostSpecificCN(X500Principal principal) {
        if (principal != null) {
            RDN[] rdns = X500Name.getInstance(principal.getEncoded()).getRDNs();
            for (int i = rdns.length - 1; i >= 0; i--) {
                AttributeTypeAndValue[] typesAndValues = rdns[i].getTypesAndValues();
                for (AttributeTypeAndValue typeAndValue : typesAndValues) {
                    if (BCStyle.CN.equals(typeAndValue.getType())) {
                        return typeAndValue.getValue().toASN1Primitive();
                    }
                }
            }
        }
        return null;
    }

    private static String getLabel(String s, int begin) {
        int end = s.indexOf(46, begin);
        if (end < 0) {
            end = s.length();
        }
        return s.substring(begin, end);
    }

    private static boolean isValidDomainName(String name) {
        try {
            new BCSNIHostName(name);
            return true;
        } catch (RuntimeException e) {
            return false;
        }
    }

    private static boolean labelMatchesPattern(String label, String pattern) {
        int wildcardPos = pattern.indexOf(42);
        if (wildcardPos < 0) {
            return label.equals(pattern);
        }
        int labelPos = 0;
        int patternPos = 0;
        do {
            String segment = pattern.substring(patternPos, wildcardPos);
            int matchPos = label.indexOf(segment, labelPos);
            if (matchPos < 0 || (patternPos == 0 && matchPos > 0)) {
                return false;
            }
            labelPos = matchPos + segment.length();
            patternPos = wildcardPos + 1;
            wildcardPos = pattern.indexOf(42, patternPos);
        } while (wildcardPos >= 0);
        return label.substring(labelPos).endsWith(pattern.substring(patternPos));
    }

    private static boolean matchesDNSName(String hostname, String dnsName, boolean allWildcards) {
        try {
            String hostname2 = IDNUtil.toUnicode(IDNUtil.toASCII(hostname, 0), 0);
            String dnsName2 = IDNUtil.toUnicode(IDNUtil.toASCII(dnsName, 0), 0);
            if (!validateWildcards(dnsName2) || !isValidDomainName(dnsName2.replace('*', 'z'))) {
                return false;
            }
            String hostname3 = hostname2.toLowerCase(Locale.ENGLISH);
            String dnsName3 = dnsName2.toLowerCase(Locale.ENGLISH);
            if (allWildcards) {
                return matchesWildcardsAllLabels(hostname3, dnsName3);
            }
            return matchesWildcardsFirstLabel(hostname3, dnsName3);
        } catch (RuntimeException e) {
            return false;
        }
    }

    private static boolean matchesWildcardsAllLabels(String hostname, String dnsName) {
        StringTokenizer st1 = new StringTokenizer(hostname, ".");
        StringTokenizer st2 = new StringTokenizer(dnsName, ".");
        if (st1.countTokens() != st2.countTokens()) {
            return false;
        }
        while (st1.hasMoreTokens()) {
            if (!labelMatchesPattern(st1.nextToken(), st2.nextToken())) {
                return false;
            }
        }
        return true;
    }

    private static boolean matchesWildcardsFirstLabel(String hostname, String dnsName) {
        String hostnameLabel = getLabel(hostname, 0);
        String dnsNameLabel = getLabel(dnsName, 0);
        if (!labelMatchesPattern(hostnameLabel, dnsNameLabel)) {
            return false;
        }
        return hostname.substring(hostnameLabel.length()).equals(dnsName.substring(dnsNameLabel.length()));
    }

    private static boolean validateWildcards(String dnsName) {
        int wildCardIndex = dnsName.lastIndexOf(42);
        if (wildCardIndex < 0 || (!dnsName.equals("*") && !dnsName.equals("*.") && dnsName.indexOf(46, wildCardIndex + 1) >= 0)) {
            return true;
        }
        return false;
    }
}
