package com.mi.car.jsse.easysec.asn1.x509;

import com.mi.car.jsse.easysec.asn1.ASN1Encodable;
import com.mi.car.jsse.easysec.asn1.ASN1EncodableVector;
import com.mi.car.jsse.easysec.asn1.ASN1Integer;
import com.mi.car.jsse.easysec.asn1.ASN1Object;
import com.mi.car.jsse.easysec.asn1.ASN1OctetString;
import com.mi.car.jsse.easysec.asn1.ASN1Primitive;
import com.mi.car.jsse.easysec.asn1.ASN1Sequence;
import com.mi.car.jsse.easysec.asn1.ASN1TaggedObject;
import com.mi.car.jsse.easysec.asn1.DEROctetString;
import com.mi.car.jsse.easysec.asn1.DERSequence;
import com.mi.car.jsse.easysec.asn1.DERTaggedObject;
import com.mi.car.jsse.easysec.crypto.Digest;
import com.mi.car.jsse.easysec.crypto.digests.SHA1Digest;
import com.mi.car.jsse.easysec.util.Arrays;
import com.mi.car.jsse.easysec.util.encoders.Hex;
import java.math.BigInteger;
import java.util.Enumeration;

public class AuthorityKeyIdentifier extends ASN1Object {
    GeneralNames certissuer;
    ASN1Integer certserno;
    ASN1OctetString keyidentifier;

    public static AuthorityKeyIdentifier getInstance(ASN1TaggedObject obj, boolean explicit) {
        return getInstance(ASN1Sequence.getInstance(obj, explicit));
    }

    public static AuthorityKeyIdentifier getInstance(Object obj) {
        if (obj instanceof AuthorityKeyIdentifier) {
            return (AuthorityKeyIdentifier) obj;
        }
        if (obj != null) {
            return new AuthorityKeyIdentifier(ASN1Sequence.getInstance(obj));
        }
        return null;
    }

    public static AuthorityKeyIdentifier fromExtensions(Extensions extensions) {
        return getInstance(Extensions.getExtensionParsedValue(extensions, Extension.authorityKeyIdentifier));
    }

    protected AuthorityKeyIdentifier(ASN1Sequence seq) {
        this.keyidentifier = null;
        this.certissuer = null;
        this.certserno = null;
        Enumeration e = seq.getObjects();
        while (e.hasMoreElements()) {
            ASN1TaggedObject o = ASN1TaggedObject.getInstance(e.nextElement());
            switch (o.getTagNo()) {
                case 0:
                    this.keyidentifier = ASN1OctetString.getInstance(o, false);
                    break;
                case 1:
                    this.certissuer = GeneralNames.getInstance(o, false);
                    break;
                case 2:
                    this.certserno = ASN1Integer.getInstance(o, false);
                    break;
                default:
                    throw new IllegalArgumentException("illegal tag");
            }
        }
    }

    public AuthorityKeyIdentifier(SubjectPublicKeyInfo spki) {
        this(spki, (GeneralNames) null, (BigInteger) null);
    }

    public AuthorityKeyIdentifier(SubjectPublicKeyInfo spki, GeneralNames name, BigInteger serialNumber) {
        ASN1Integer aSN1Integer = null;
        this.keyidentifier = null;
        this.certissuer = null;
        this.certserno = null;
        Digest digest = new SHA1Digest();
        byte[] resBuf = new byte[digest.getDigestSize()];
        byte[] bytes = spki.getPublicKeyData().getBytes();
        digest.update(bytes, 0, bytes.length);
        digest.doFinal(resBuf, 0);
        this.keyidentifier = new DEROctetString(resBuf);
        this.certissuer = name;
        this.certserno = serialNumber != null ? new ASN1Integer(serialNumber) : aSN1Integer;
    }

    public AuthorityKeyIdentifier(GeneralNames name, BigInteger serialNumber) {
        this((byte[]) null, name, serialNumber);
    }

    public AuthorityKeyIdentifier(byte[] keyIdentifier) {
        this(keyIdentifier, (GeneralNames) null, (BigInteger) null);
    }

    public AuthorityKeyIdentifier(byte[] keyIdentifier, GeneralNames name, BigInteger serialNumber) {
        DEROctetString dEROctetString;
        ASN1Integer aSN1Integer = null;
        this.keyidentifier = null;
        this.certissuer = null;
        this.certserno = null;
        if (keyIdentifier != null) {
            dEROctetString = new DEROctetString(Arrays.clone(keyIdentifier));
        } else {
            dEROctetString = null;
        }
        this.keyidentifier = dEROctetString;
        this.certissuer = name;
        this.certserno = serialNumber != null ? new ASN1Integer(serialNumber) : aSN1Integer;
    }

    public byte[] getKeyIdentifier() {
        if (this.keyidentifier != null) {
            return this.keyidentifier.getOctets();
        }
        return null;
    }

    public GeneralNames getAuthorityCertIssuer() {
        return this.certissuer;
    }

    public BigInteger getAuthorityCertSerialNumber() {
        if (this.certserno != null) {
            return this.certserno.getValue();
        }
        return null;
    }

    @Override // com.mi.car.jsse.easysec.asn1.ASN1Object, com.mi.car.jsse.easysec.asn1.ASN1Encodable
    public ASN1Primitive toASN1Primitive() {
        ASN1EncodableVector v = new ASN1EncodableVector(3);
        if (this.keyidentifier != null) {
            v.add(new DERTaggedObject(false, 0, (ASN1Encodable) this.keyidentifier));
        }
        if (this.certissuer != null) {
            v.add(new DERTaggedObject(false, 1, (ASN1Encodable) this.certissuer));
        }
        if (this.certserno != null) {
            v.add(new DERTaggedObject(false, 2, (ASN1Encodable) this.certserno));
        }
        return new DERSequence(v);
    }

    public String toString() {
        return "AuthorityKeyIdentifier: KeyID(" + (this.keyidentifier != null ? Hex.toHexString(this.keyidentifier.getOctets()) : "null") + ")";
    }
}
