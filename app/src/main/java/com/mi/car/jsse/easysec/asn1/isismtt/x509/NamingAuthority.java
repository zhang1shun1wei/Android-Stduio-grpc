package com.mi.car.jsse.easysec.asn1.isismtt.x509;

import com.mi.car.jsse.easysec.asn1.ASN1Encodable;
import com.mi.car.jsse.easysec.asn1.ASN1EncodableVector;
import com.mi.car.jsse.easysec.asn1.ASN1IA5String;
import com.mi.car.jsse.easysec.asn1.ASN1Object;
import com.mi.car.jsse.easysec.asn1.ASN1ObjectIdentifier;
import com.mi.car.jsse.easysec.asn1.ASN1Primitive;
import com.mi.car.jsse.easysec.asn1.ASN1Sequence;
import com.mi.car.jsse.easysec.asn1.ASN1String;
import com.mi.car.jsse.easysec.asn1.ASN1TaggedObject;
import com.mi.car.jsse.easysec.asn1.DERIA5String;
import com.mi.car.jsse.easysec.asn1.DERSequence;
import com.mi.car.jsse.easysec.asn1.isismtt.ISISMTTObjectIdentifiers;
import com.mi.car.jsse.easysec.asn1.x500.DirectoryString;
import java.util.Enumeration;

public class NamingAuthority extends ASN1Object {
    public static final ASN1ObjectIdentifier id_isismtt_at_namingAuthorities_RechtWirtschaftSteuern = new ASN1ObjectIdentifier(ISISMTTObjectIdentifiers.id_isismtt_at_namingAuthorities + ".1");
    private ASN1ObjectIdentifier namingAuthorityId;
    private DirectoryString namingAuthorityText;
    private String namingAuthorityUrl;

    public static NamingAuthority getInstance(Object obj) {
        if (obj == null || (obj instanceof NamingAuthority)) {
            return (NamingAuthority) obj;
        }
        if (obj instanceof ASN1Sequence) {
            return new NamingAuthority((ASN1Sequence) obj);
        }
        throw new IllegalArgumentException("illegal object in getInstance: " + obj.getClass().getName());
    }

    public static NamingAuthority getInstance(ASN1TaggedObject obj, boolean explicit) {
        return getInstance(ASN1Sequence.getInstance(obj, explicit));
    }

    private NamingAuthority(ASN1Sequence seq) {
        if (seq.size() > 3) {
            throw new IllegalArgumentException("Bad sequence size: " + seq.size());
        }
        Enumeration e = seq.getObjects();
        if (e.hasMoreElements()) {
            ASN1Encodable o = (ASN1Encodable) e.nextElement();
            if (o instanceof ASN1ObjectIdentifier) {
                this.namingAuthorityId = (ASN1ObjectIdentifier) o;
            } else if (o instanceof ASN1IA5String) {
                this.namingAuthorityUrl = ASN1IA5String.getInstance(o).getString();
            } else if (o instanceof ASN1String) {
                this.namingAuthorityText = DirectoryString.getInstance(o);
            } else {
                throw new IllegalArgumentException("Bad object encountered: " + o.getClass());
            }
        }
        if (e.hasMoreElements()) {
            ASN1Encodable o2 = (ASN1Encodable) e.nextElement();
            if (o2 instanceof ASN1IA5String) {
                this.namingAuthorityUrl = ASN1IA5String.getInstance(o2).getString();
            } else if (o2 instanceof ASN1String) {
                this.namingAuthorityText = DirectoryString.getInstance(o2);
            } else {
                throw new IllegalArgumentException("Bad object encountered: " + o2.getClass());
            }
        }
        if (e.hasMoreElements()) {
            ASN1Encodable o3 = (ASN1Encodable) e.nextElement();
            if (o3 instanceof ASN1String) {
                this.namingAuthorityText = DirectoryString.getInstance(o3);
                return;
            }
            throw new IllegalArgumentException("Bad object encountered: " + o3.getClass());
        }
    }

    public ASN1ObjectIdentifier getNamingAuthorityId() {
        return this.namingAuthorityId;
    }

    public DirectoryString getNamingAuthorityText() {
        return this.namingAuthorityText;
    }

    public String getNamingAuthorityUrl() {
        return this.namingAuthorityUrl;
    }

    public NamingAuthority(ASN1ObjectIdentifier namingAuthorityId2, String namingAuthorityUrl2, DirectoryString namingAuthorityText2) {
        this.namingAuthorityId = namingAuthorityId2;
        this.namingAuthorityUrl = namingAuthorityUrl2;
        this.namingAuthorityText = namingAuthorityText2;
    }

    public ASN1Primitive toASN1Primitive() {
        ASN1EncodableVector vec = new ASN1EncodableVector(3);
        if (this.namingAuthorityId != null) {
            vec.add(this.namingAuthorityId);
        }
        if (this.namingAuthorityUrl != null) {
            vec.add(new DERIA5String(this.namingAuthorityUrl, true));
        }
        if (this.namingAuthorityText != null) {
            vec.add(this.namingAuthorityText);
        }
        return new DERSequence(vec);
    }
}
