package com.mi.car.jsse.easysec.asn1.x509;

import com.mi.car.jsse.easysec.asn1.ASN1Encodable;
import com.mi.car.jsse.easysec.asn1.ASN1EncodableVector;
import com.mi.car.jsse.easysec.asn1.ASN1Object;
import com.mi.car.jsse.easysec.asn1.ASN1ObjectIdentifier;
import com.mi.car.jsse.easysec.asn1.ASN1Primitive;
import com.mi.car.jsse.easysec.asn1.ASN1Sequence;
import com.mi.car.jsse.easysec.asn1.ASN1TaggedObject;
import com.mi.car.jsse.easysec.asn1.DERSequence;
import java.util.Enumeration;
import java.util.Hashtable;
import java.util.Vector;

public class Extensions extends ASN1Object {
    private Hashtable extensions = new Hashtable();
    private Vector ordering = new Vector();

    public static Extension getExtension(Extensions extensions2, ASN1ObjectIdentifier oid) {
        if (extensions2 == null) {
            return null;
        }
        return extensions2.getExtension(oid);
    }

    public static ASN1Encodable getExtensionParsedValue(Extensions extensions2, ASN1ObjectIdentifier oid) {
        if (extensions2 == null) {
            return null;
        }
        return extensions2.getExtensionParsedValue(oid);
    }

    public static Extensions getInstance(ASN1TaggedObject obj, boolean explicit) {
        return getInstance(ASN1Sequence.getInstance(obj, explicit));
    }

    public static Extensions getInstance(Object obj) {
        if (obj instanceof Extensions) {
            return (Extensions) obj;
        }
        if (obj != null) {
            return new Extensions(ASN1Sequence.getInstance(obj));
        }
        return null;
    }

    private Extensions(ASN1Sequence seq) {
        Enumeration e = seq.getObjects();
        while (e.hasMoreElements()) {
            Extension ext = Extension.getInstance(e.nextElement());
            if (this.extensions.containsKey(ext.getExtnId())) {
                throw new IllegalArgumentException("repeated extension found: " + ext.getExtnId());
            }
            this.extensions.put(ext.getExtnId(), ext);
            this.ordering.addElement(ext.getExtnId());
        }
    }

    public Extensions(Extension extension) {
        this.ordering.addElement(extension.getExtnId());
        this.extensions.put(extension.getExtnId(), extension);
    }

    public Extensions(Extension[] extensions2) {
        for (int i = 0; i != extensions2.length; i++) {
            Extension ext = extensions2[i];
            this.ordering.addElement(ext.getExtnId());
            this.extensions.put(ext.getExtnId(), ext);
        }
    }

    public Enumeration oids() {
        return this.ordering.elements();
    }

    public Extension getExtension(ASN1ObjectIdentifier oid) {
        return (Extension) this.extensions.get(oid);
    }

    public ASN1Encodable getExtensionParsedValue(ASN1ObjectIdentifier oid) {
        Extension ext = getExtension(oid);
        if (ext != null) {
            return ext.getParsedValue();
        }
        return null;
    }

    @Override // com.mi.car.jsse.easysec.asn1.ASN1Object, com.mi.car.jsse.easysec.asn1.ASN1Encodable
    public ASN1Primitive toASN1Primitive() {
        ASN1EncodableVector vec = new ASN1EncodableVector(this.ordering.size());
        Enumeration e = this.ordering.elements();
        while (e.hasMoreElements()) {
            vec.add((Extension) this.extensions.get((ASN1ObjectIdentifier) e.nextElement()));
        }
        return new DERSequence(vec);
    }

    public boolean equivalent(Extensions other) {
        if (this.extensions.size() != other.extensions.size()) {
            return false;
        }
        Enumeration e1 = this.extensions.keys();
        while (e1.hasMoreElements()) {
            Object key = e1.nextElement();
            if (!this.extensions.get(key).equals(other.extensions.get(key))) {
                return false;
            }
        }
        return true;
    }

    public ASN1ObjectIdentifier[] getExtensionOIDs() {
        return toOidArray(this.ordering);
    }

    public ASN1ObjectIdentifier[] getNonCriticalExtensionOIDs() {
        return getExtensionOIDs(false);
    }

    public ASN1ObjectIdentifier[] getCriticalExtensionOIDs() {
        return getExtensionOIDs(true);
    }

    private ASN1ObjectIdentifier[] getExtensionOIDs(boolean isCritical) {
        Vector oidVec = new Vector();
        for (int i = 0; i != this.ordering.size(); i++) {
            Object oid = this.ordering.elementAt(i);
            if (((Extension) this.extensions.get(oid)).isCritical() == isCritical) {
                oidVec.addElement(oid);
            }
        }
        return toOidArray(oidVec);
    }

    private ASN1ObjectIdentifier[] toOidArray(Vector oidVec) {
        ASN1ObjectIdentifier[] oids = new ASN1ObjectIdentifier[oidVec.size()];
        for (int i = 0; i != oids.length; i++) {
            oids[i] = (ASN1ObjectIdentifier) oidVec.elementAt(i);
        }
        return oids;
    }
}
