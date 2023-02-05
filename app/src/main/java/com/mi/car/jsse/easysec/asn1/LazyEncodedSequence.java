package com.mi.car.jsse.easysec.asn1;

import java.io.IOException;
import java.util.Enumeration;
import java.util.Iterator;

class LazyEncodedSequence extends ASN1Sequence {
    private byte[] encoded;

    LazyEncodedSequence(byte[] encoded2) throws IOException {
        if (encoded2 == null) {
            throw new NullPointerException("'encoded' cannot be null");
        }
        this.encoded = encoded2;
    }

    @Override // com.mi.car.jsse.easysec.asn1.ASN1Sequence
    public ASN1Encodable getObjectAt(int index) {
        force();
        return super.getObjectAt(index);
    }

    @Override // com.mi.car.jsse.easysec.asn1.ASN1Sequence
    public Enumeration getObjects() {
        byte[] encoded2 = getContents();
        if (encoded2 != null) {
            return new LazyConstructionEnumeration(encoded2);
        }
        return super.getObjects();
    }

    @Override // com.mi.car.jsse.easysec.asn1.ASN1Object, com.mi.car.jsse.easysec.asn1.ASN1Sequence, com.mi.car.jsse.easysec.asn1.ASN1Primitive
    public int hashCode() {
        force();
        return super.hashCode();
    }

    @Override // com.mi.car.jsse.easysec.util.Iterable, com.mi.car.jsse.easysec.asn1.ASN1Sequence, java.lang.Iterable
    public Iterator<ASN1Encodable> iterator() {
        force();
        return super.iterator();
    }

    @Override // com.mi.car.jsse.easysec.asn1.ASN1Sequence
    public int size() {
        force();
        return super.size();
    }

    @Override // com.mi.car.jsse.easysec.asn1.ASN1Sequence
    public ASN1Encodable[] toArray() {
        force();
        return super.toArray();
    }

    /* access modifiers changed from: package-private */
    @Override // com.mi.car.jsse.easysec.asn1.ASN1Sequence
    public ASN1Encodable[] toArrayInternal() {
        force();
        return super.toArrayInternal();
    }

    /* access modifiers changed from: package-private */
    @Override // com.mi.car.jsse.easysec.asn1.ASN1Primitive
    public int encodedLength(boolean withTag) throws IOException {
        byte[] encoded2 = getContents();
        if (encoded2 != null) {
            return ASN1OutputStream.getLengthOfEncodingDL(withTag, encoded2.length);
        }
        return super.toDLObject().encodedLength(withTag);
    }

    /* access modifiers changed from: package-private */
    @Override // com.mi.car.jsse.easysec.asn1.ASN1Primitive
    public void encode(ASN1OutputStream out, boolean withTag) throws IOException {
        byte[] encoded2 = getContents();
        if (encoded2 != null) {
            out.writeEncodingDL(withTag, 48, encoded2);
        } else {
            super.toDLObject().encode(out, withTag);
        }
    }

    /* access modifiers changed from: package-private */
    @Override // com.mi.car.jsse.easysec.asn1.ASN1Sequence
    public ASN1BitString toASN1BitString() {
        return ((ASN1Sequence) toDLObject()).toASN1BitString();
    }

    /* access modifiers changed from: package-private */
    @Override // com.mi.car.jsse.easysec.asn1.ASN1Sequence
    public ASN1External toASN1External() {
        return ((ASN1Sequence) toDLObject()).toASN1External();
    }

    /* access modifiers changed from: package-private */
    @Override // com.mi.car.jsse.easysec.asn1.ASN1Sequence
    public ASN1OctetString toASN1OctetString() {
        return ((ASN1Sequence) toDLObject()).toASN1OctetString();
    }

    /* access modifiers changed from: package-private */
    @Override // com.mi.car.jsse.easysec.asn1.ASN1Sequence
    public ASN1Set toASN1Set() {
        return ((ASN1Sequence) toDLObject()).toASN1Set();
    }

    /* access modifiers changed from: package-private */
    @Override // com.mi.car.jsse.easysec.asn1.ASN1Sequence, com.mi.car.jsse.easysec.asn1.ASN1Primitive
    public ASN1Primitive toDERObject() {
        force();
        return super.toDERObject();
    }

    /* access modifiers changed from: package-private */
    @Override // com.mi.car.jsse.easysec.asn1.ASN1Sequence, com.mi.car.jsse.easysec.asn1.ASN1Primitive
    public ASN1Primitive toDLObject() {
        force();
        return super.toDLObject();
    }

    private synchronized void force() {
        if (this.encoded != null) {
            ASN1InputStream aIn = new ASN1InputStream(this.encoded, true);
            try {
                ASN1EncodableVector v = aIn.readVector();
                aIn.close();
                this.elements = v.takeElements();
                this.encoded = null;
            } catch (IOException e) {
                throw new ASN1ParsingException("malformed ASN.1: " + e, e);
            }
        }
    }

    private synchronized byte[] getContents() {
        return this.encoded;
    }
}
