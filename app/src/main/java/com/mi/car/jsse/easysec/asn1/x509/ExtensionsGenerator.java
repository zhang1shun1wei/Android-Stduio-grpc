package com.mi.car.jsse.easysec.asn1.x509;

import com.mi.car.jsse.easysec.asn1.ASN1Encodable;
import com.mi.car.jsse.easysec.asn1.ASN1EncodableVector;
import com.mi.car.jsse.easysec.asn1.ASN1Encoding;
import com.mi.car.jsse.easysec.asn1.ASN1ObjectIdentifier;
import com.mi.car.jsse.easysec.asn1.ASN1ParsingException;
import com.mi.car.jsse.easysec.asn1.ASN1Sequence;
import com.mi.car.jsse.easysec.asn1.DEROctetString;
import com.mi.car.jsse.easysec.asn1.DERSequence;
import com.mi.car.jsse.easysec.util.Arrays;
import java.io.IOException;
import java.util.Collections;
import java.util.Enumeration;
import java.util.HashSet;
import java.util.Hashtable;
import java.util.Set;
import java.util.Vector;

public class ExtensionsGenerator {
    private static final Set dupsAllowed;
    private Vector extOrdering = new Vector();
    private Hashtable extensions = new Hashtable();

    static {
        Set dups = new HashSet();
        dups.add(Extension.subjectAlternativeName);
        dups.add(Extension.issuerAlternativeName);
        dups.add(Extension.subjectDirectoryAttributes);
        dups.add(Extension.certificateIssuer);
        dupsAllowed = Collections.unmodifiableSet(dups);
    }

    public void reset() {
        this.extensions = new Hashtable();
        this.extOrdering = new Vector();
    }

    public void addExtension(ASN1ObjectIdentifier oid, boolean critical, ASN1Encodable value) throws IOException {
        addExtension(oid, critical, value.toASN1Primitive().getEncoded(ASN1Encoding.DER));
    }

    public void addExtension(ASN1ObjectIdentifier oid, boolean critical, byte[] value) {
        if (!this.extensions.containsKey(oid)) {
            this.extOrdering.addElement(oid);
            this.extensions.put(oid, new Extension(oid, critical, new DEROctetString(Arrays.clone(value))));
        } else if (dupsAllowed.contains(oid)) {
            ASN1Sequence seq1 = ASN1Sequence.getInstance(DEROctetString.getInstance(((Extension) this.extensions.get(oid)).getExtnValue()).getOctets());
            ASN1Sequence seq2 = ASN1Sequence.getInstance(value);
            ASN1EncodableVector items = new ASN1EncodableVector(seq1.size() + seq2.size());
            Enumeration en = seq1.getObjects();
            while (en.hasMoreElements()) {
                items.add((ASN1Encodable) en.nextElement());
            }
            Enumeration en2 = seq2.getObjects();
            while (en2.hasMoreElements()) {
                items.add((ASN1Encodable) en2.nextElement());
            }
            try {
                this.extensions.put(oid, new Extension(oid, critical, new DERSequence(items).getEncoded()));
            } catch (IOException e) {
                throw new ASN1ParsingException(e.getMessage(), e);
            }
        } else {
            throw new IllegalArgumentException("extension " + oid + " already added");
        }
    }

    public void addExtension(Extension extension) {
        if (this.extensions.containsKey(extension.getExtnId())) {
            throw new IllegalArgumentException("extension " + extension.getExtnId() + " already added");
        }
        this.extOrdering.addElement(extension.getExtnId());
        this.extensions.put(extension.getExtnId(), extension);
    }

    public void replaceExtension(ASN1ObjectIdentifier oid, boolean critical, ASN1Encodable value) throws IOException {
        replaceExtension(oid, critical, value.toASN1Primitive().getEncoded(ASN1Encoding.DER));
    }

    public void replaceExtension(ASN1ObjectIdentifier oid, boolean critical, byte[] value) {
        replaceExtension(new Extension(oid, critical, value));
    }

    public void replaceExtension(Extension extension) {
        if (!this.extensions.containsKey(extension.getExtnId())) {
            throw new IllegalArgumentException("extension " + extension.getExtnId() + " not present");
        }
        this.extensions.put(extension.getExtnId(), extension);
    }

    public void removeExtension(ASN1ObjectIdentifier oid) {
        if (!this.extensions.containsKey(oid)) {
            throw new IllegalArgumentException("extension " + oid + " not present");
        }
        this.extOrdering.removeElement(oid);
        this.extensions.remove(oid);
    }

    public boolean hasExtension(ASN1ObjectIdentifier oid) {
        return this.extensions.containsKey(oid);
    }

    public Extension getExtension(ASN1ObjectIdentifier oid) {
        return (Extension) this.extensions.get(oid);
    }

    public boolean isEmpty() {
        return this.extOrdering.isEmpty();
    }

    public Extensions generate() {
        Extension[] exts = new Extension[this.extOrdering.size()];
        for (int i = 0; i != this.extOrdering.size(); i++) {
            exts[i] = (Extension) this.extensions.get(this.extOrdering.elementAt(i));
        }
        return new Extensions(exts);
    }

    public void addExtension(Extensions extensions2) {
        ASN1ObjectIdentifier[] oids = extensions2.getExtensionOIDs();
        for (int i = 0; i != oids.length; i++) {
            ASN1ObjectIdentifier ident = oids[i];
            Extension ext = extensions2.getExtension(ident);
            addExtension(ASN1ObjectIdentifier.getInstance(ident), ext.isCritical(), ext.getExtnValue().getOctets());
        }
    }
}
