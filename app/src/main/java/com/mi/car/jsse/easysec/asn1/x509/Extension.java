package com.mi.car.jsse.easysec.asn1.x509;

import com.mi.car.jsse.easysec.asn1.ASN1Boolean;
import com.mi.car.jsse.easysec.asn1.ASN1Encodable;
import com.mi.car.jsse.easysec.asn1.ASN1EncodableVector;
import com.mi.car.jsse.easysec.asn1.ASN1Object;
import com.mi.car.jsse.easysec.asn1.ASN1ObjectIdentifier;
import com.mi.car.jsse.easysec.asn1.ASN1OctetString;
import com.mi.car.jsse.easysec.asn1.ASN1Primitive;
import com.mi.car.jsse.easysec.asn1.ASN1Sequence;
import com.mi.car.jsse.easysec.asn1.DEROctetString;
import com.mi.car.jsse.easysec.asn1.DERSequence;
import com.mi.car.jsse.easysec.util.Arrays;
import java.io.IOException;

public class Extension extends ASN1Object {
    public static final ASN1ObjectIdentifier auditIdentity = new ASN1ObjectIdentifier("1.3.6.1.5.5.7.1.4").intern();
    public static final ASN1ObjectIdentifier authorityInfoAccess = new ASN1ObjectIdentifier("1.3.6.1.5.5.7.1.1").intern();
    public static final ASN1ObjectIdentifier authorityKeyIdentifier = new ASN1ObjectIdentifier("2.5.29.35").intern();
    public static final ASN1ObjectIdentifier basicConstraints = new ASN1ObjectIdentifier("2.5.29.19").intern();
    public static final ASN1ObjectIdentifier biometricInfo = new ASN1ObjectIdentifier("1.3.6.1.5.5.7.1.2").intern();
    public static final ASN1ObjectIdentifier cRLDistributionPoints = new ASN1ObjectIdentifier("2.5.29.31").intern();
    public static final ASN1ObjectIdentifier cRLNumber = new ASN1ObjectIdentifier("2.5.29.20").intern();
    public static final ASN1ObjectIdentifier certificateIssuer = new ASN1ObjectIdentifier("2.5.29.29").intern();
    public static final ASN1ObjectIdentifier certificatePolicies = new ASN1ObjectIdentifier("2.5.29.32").intern();
    public static final ASN1ObjectIdentifier deltaCRLIndicator = new ASN1ObjectIdentifier("2.5.29.27").intern();
    public static final ASN1ObjectIdentifier expiredCertsOnCRL = new ASN1ObjectIdentifier("2.5.29.60").intern();
    public static final ASN1ObjectIdentifier extendedKeyUsage = new ASN1ObjectIdentifier("2.5.29.37").intern();
    public static final ASN1ObjectIdentifier freshestCRL = new ASN1ObjectIdentifier("2.5.29.46").intern();
    public static final ASN1ObjectIdentifier inhibitAnyPolicy = new ASN1ObjectIdentifier("2.5.29.54").intern();
    public static final ASN1ObjectIdentifier instructionCode = new ASN1ObjectIdentifier("2.5.29.23").intern();
    public static final ASN1ObjectIdentifier invalidityDate = new ASN1ObjectIdentifier("2.5.29.24").intern();
    public static final ASN1ObjectIdentifier issuerAlternativeName = new ASN1ObjectIdentifier("2.5.29.18").intern();
    public static final ASN1ObjectIdentifier issuingDistributionPoint = new ASN1ObjectIdentifier("2.5.29.28").intern();
    public static final ASN1ObjectIdentifier keyUsage = new ASN1ObjectIdentifier("2.5.29.15").intern();
    public static final ASN1ObjectIdentifier logoType = new ASN1ObjectIdentifier("1.3.6.1.5.5.7.1.12").intern();
    public static final ASN1ObjectIdentifier nameConstraints = new ASN1ObjectIdentifier("2.5.29.30").intern();
    public static final ASN1ObjectIdentifier noRevAvail = new ASN1ObjectIdentifier("2.5.29.56").intern();
    public static final ASN1ObjectIdentifier policyConstraints = new ASN1ObjectIdentifier("2.5.29.36").intern();
    public static final ASN1ObjectIdentifier policyMappings = new ASN1ObjectIdentifier("2.5.29.33").intern();
    public static final ASN1ObjectIdentifier privateKeyUsagePeriod = new ASN1ObjectIdentifier("2.5.29.16").intern();
    public static final ASN1ObjectIdentifier qCStatements = new ASN1ObjectIdentifier("1.3.6.1.5.5.7.1.3").intern();
    public static final ASN1ObjectIdentifier reasonCode = new ASN1ObjectIdentifier("2.5.29.21").intern();
    public static final ASN1ObjectIdentifier subjectAlternativeName = new ASN1ObjectIdentifier("2.5.29.17").intern();
    public static final ASN1ObjectIdentifier subjectDirectoryAttributes = new ASN1ObjectIdentifier("2.5.29.9").intern();
    public static final ASN1ObjectIdentifier subjectInfoAccess = new ASN1ObjectIdentifier("1.3.6.1.5.5.7.1.11").intern();
    public static final ASN1ObjectIdentifier subjectKeyIdentifier = new ASN1ObjectIdentifier("2.5.29.14").intern();
    public static final ASN1ObjectIdentifier targetInformation = new ASN1ObjectIdentifier("2.5.29.55").intern();
    private boolean critical;
    private ASN1ObjectIdentifier extnId;
    private ASN1OctetString value;

    public Extension(ASN1ObjectIdentifier extnId2, ASN1Boolean critical2, ASN1OctetString value2) {
        this(extnId2, critical2.isTrue(), value2);
    }

    public Extension(ASN1ObjectIdentifier extnId2, boolean critical2, byte[] value2) {
        this(extnId2, critical2, new DEROctetString(Arrays.clone(value2)));
    }

    public Extension(ASN1ObjectIdentifier extnId2, boolean critical2, ASN1OctetString value2) {
        this.extnId = extnId2;
        this.critical = critical2;
        this.value = value2;
    }

    public static Extension create(ASN1ObjectIdentifier extnId2, boolean critical2, ASN1Encodable value2) throws IOException {
        return new Extension(extnId2, critical2, value2.toASN1Primitive().getEncoded());
    }

    private Extension(ASN1Sequence seq) {
        if (seq.size() == 2) {
            this.extnId = ASN1ObjectIdentifier.getInstance(seq.getObjectAt(0));
            this.critical = false;
            this.value = ASN1OctetString.getInstance(seq.getObjectAt(1));
        } else if (seq.size() == 3) {
            this.extnId = ASN1ObjectIdentifier.getInstance(seq.getObjectAt(0));
            this.critical = ASN1Boolean.getInstance(seq.getObjectAt(1)).isTrue();
            this.value = ASN1OctetString.getInstance(seq.getObjectAt(2));
        } else {
            throw new IllegalArgumentException("Bad sequence size: " + seq.size());
        }
    }

    public static Extension getInstance(Object obj) {
        if (obj instanceof Extension) {
            return (Extension) obj;
        }
        if (obj != null) {
            return new Extension(ASN1Sequence.getInstance(obj));
        }
        return null;
    }

    public ASN1ObjectIdentifier getExtnId() {
        return this.extnId;
    }

    public boolean isCritical() {
        return this.critical;
    }

    public ASN1OctetString getExtnValue() {
        return this.value;
    }

    public ASN1Encodable getParsedValue() {
        return convertValueToObject(this);
    }

    @Override // com.mi.car.jsse.easysec.asn1.ASN1Object
    public int hashCode() {
        if (isCritical()) {
            return getExtnValue().hashCode() ^ getExtnId().hashCode();
        }
        return (getExtnValue().hashCode() ^ getExtnId().hashCode()) ^ -1;
    }

    @Override // com.mi.car.jsse.easysec.asn1.ASN1Object
    public boolean equals(Object o) {
        if (!(o instanceof Extension)) {
            return false;
        }
        Extension other = (Extension) o;
        if (!other.getExtnId().equals((ASN1Primitive) getExtnId()) || !other.getExtnValue().equals((ASN1Primitive) getExtnValue()) || other.isCritical() != isCritical()) {
            return false;
        }
        return true;
    }

    @Override // com.mi.car.jsse.easysec.asn1.ASN1Object, com.mi.car.jsse.easysec.asn1.ASN1Encodable
    public ASN1Primitive toASN1Primitive() {
        ASN1EncodableVector v = new ASN1EncodableVector(3);
        v.add(this.extnId);
        if (this.critical) {
            v.add(ASN1Boolean.getInstance(true));
        }
        v.add(this.value);
        return new DERSequence(v);
    }

    private static ASN1Primitive convertValueToObject(Extension ext) throws IllegalArgumentException {
        try {
            return ASN1Primitive.fromByteArray(ext.getExtnValue().getOctets());
        } catch (IOException e) {
            throw new IllegalArgumentException("can't convert extension: " + e);
        }
    }
}
