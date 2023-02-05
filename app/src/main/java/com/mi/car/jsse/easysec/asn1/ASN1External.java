package com.mi.car.jsse.easysec.asn1;

import com.mi.car.jsse.easysec.util.Objects;
import java.io.IOException;

public abstract class ASN1External extends ASN1Primitive {
    static final ASN1UniversalType TYPE = new ASN1UniversalType(ASN1External.class, 8) {
        /* class com.mi.car.jsse.easysec.asn1.ASN1External.AnonymousClass1 */

        /* access modifiers changed from: package-private */
        @Override // com.mi.car.jsse.easysec.asn1.ASN1UniversalType
        public ASN1Primitive fromImplicitConstructed(ASN1Sequence sequence) {
            return sequence.toASN1External();
        }
    };
    ASN1Primitive dataValueDescriptor;
    ASN1ObjectIdentifier directReference;
    int encoding;
    ASN1Primitive externalContent;
    ASN1Integer indirectReference;

    /* access modifiers changed from: package-private */
    public abstract ASN1Sequence buildSequence();

    public static ASN1External getInstance(Object obj) {
        if (obj == null || (obj instanceof ASN1External)) {
            return (ASN1External) obj;
        }
        if (obj instanceof ASN1Encodable) {
            ASN1Primitive primitive = ((ASN1Encodable) obj).toASN1Primitive();
            if (primitive instanceof ASN1External) {
                return (ASN1External) primitive;
            }
        } else if (obj instanceof byte[]) {
            try {
                return (ASN1External) TYPE.fromByteArray((byte[]) obj);
            } catch (IOException e) {
                throw new IllegalArgumentException("failed to construct external from byte[]: " + e.getMessage());
            }
        }
        throw new IllegalArgumentException("illegal object in getInstance: " + obj.getClass().getName());
    }

    public static ASN1External getInstance(ASN1TaggedObject taggedObject, boolean explicit) {
        return (ASN1External) TYPE.getContextInstance(taggedObject, explicit);
    }

    ASN1External(ASN1Sequence sequence) {
        int offset = 0;
        ASN1Primitive asn1 = getObjFromSequence(sequence, 0);
        if (asn1 instanceof ASN1ObjectIdentifier) {
            this.directReference = (ASN1ObjectIdentifier) asn1;
            offset = 0 + 1;
            asn1 = getObjFromSequence(sequence, offset);
        }
        if (asn1 instanceof ASN1Integer) {
            this.indirectReference = (ASN1Integer) asn1;
            offset++;
            asn1 = getObjFromSequence(sequence, offset);
        }
        if (!(asn1 instanceof ASN1TaggedObject)) {
            this.dataValueDescriptor = asn1;
            offset++;
            asn1 = getObjFromSequence(sequence, offset);
        }
        if (sequence.size() != offset + 1) {
            throw new IllegalArgumentException("input sequence too large");
        } else if (!(asn1 instanceof ASN1TaggedObject)) {
            throw new IllegalArgumentException("No tagged object found in sequence. Structure doesn't seem to be of type External");
        } else {
            ASN1TaggedObject obj = (ASN1TaggedObject) asn1;
            this.encoding = checkEncoding(obj.getTagNo());
            this.externalContent = getExternalContent(obj);
        }
    }

    ASN1External(ASN1ObjectIdentifier directReference2, ASN1Integer indirectReference2, ASN1Primitive dataValueDescriptor2, DERTaggedObject externalData) {
        this.directReference = directReference2;
        this.indirectReference = indirectReference2;
        this.dataValueDescriptor = dataValueDescriptor2;
        this.encoding = checkEncoding(externalData.getTagNo());
        this.externalContent = getExternalContent(externalData);
    }

    ASN1External(ASN1ObjectIdentifier directReference2, ASN1Integer indirectReference2, ASN1Primitive dataValueDescriptor2, int encoding2, ASN1Primitive externalData) {
        this.directReference = directReference2;
        this.indirectReference = indirectReference2;
        this.dataValueDescriptor = dataValueDescriptor2;
        this.encoding = checkEncoding(encoding2);
        this.externalContent = checkExternalContent(encoding2, externalData);
    }

    /* access modifiers changed from: package-private */
    @Override // com.mi.car.jsse.easysec.asn1.ASN1Primitive
    public int encodedLength(boolean withTag) throws IOException {
        return buildSequence().encodedLength(withTag);
    }

    /* access modifiers changed from: package-private */
    @Override // com.mi.car.jsse.easysec.asn1.ASN1Primitive
    public void encode(ASN1OutputStream out, boolean withTag) throws IOException {
        out.writeIdentifier(withTag, 40);
        buildSequence().encode(out, false);
    }

    /* access modifiers changed from: package-private */
    @Override // com.mi.car.jsse.easysec.asn1.ASN1Primitive
    public ASN1Primitive toDERObject() {
        return new DERExternal(this.directReference, this.indirectReference, this.dataValueDescriptor, this.encoding, this.externalContent);
    }

    /* access modifiers changed from: package-private */
    @Override // com.mi.car.jsse.easysec.asn1.ASN1Primitive
    public ASN1Primitive toDLObject() {
        return new DLExternal(this.directReference, this.indirectReference, this.dataValueDescriptor, this.encoding, this.externalContent);
    }

    @Override // com.mi.car.jsse.easysec.asn1.ASN1Object, com.mi.car.jsse.easysec.asn1.ASN1Primitive
    public int hashCode() {
        return (((Objects.hashCode(this.directReference) ^ Objects.hashCode(this.indirectReference)) ^ Objects.hashCode(this.dataValueDescriptor)) ^ this.encoding) ^ this.externalContent.hashCode();
    }

    /* access modifiers changed from: package-private */
    @Override // com.mi.car.jsse.easysec.asn1.ASN1Primitive
    public boolean encodeConstructed() {
        return true;
    }

    /* access modifiers changed from: package-private */
    @Override // com.mi.car.jsse.easysec.asn1.ASN1Primitive
    public boolean asn1Equals(ASN1Primitive primitive) {
        if (this == primitive) {
            return true;
        }
        if (!(primitive instanceof ASN1External)) {
            return false;
        }
        ASN1External that = (ASN1External) primitive;
        return Objects.areEqual(this.directReference, that.directReference) && Objects.areEqual(this.indirectReference, that.indirectReference) && Objects.areEqual(this.dataValueDescriptor, that.dataValueDescriptor) && this.encoding == that.encoding && this.externalContent.equals(that.externalContent);
    }

    public ASN1Primitive getDataValueDescriptor() {
        return this.dataValueDescriptor;
    }

    public ASN1ObjectIdentifier getDirectReference() {
        return this.directReference;
    }

    public int getEncoding() {
        return this.encoding;
    }

    public ASN1Primitive getExternalContent() {
        return this.externalContent;
    }

    public ASN1Integer getIndirectReference() {
        return this.indirectReference;
    }

    private static int checkEncoding(int encoding2) {
        if (encoding2 >= 0 && encoding2 <= 2) {
            return encoding2;
        }
        throw new IllegalArgumentException("invalid encoding value: " + encoding2);
    }

    private static ASN1Primitive checkExternalContent(int tagNo, ASN1Primitive externalContent2) {
        switch (tagNo) {
            case 1:
                return ASN1OctetString.TYPE.checkedCast(externalContent2);
            case 2:
                return ASN1BitString.TYPE.checkedCast(externalContent2);
            default:
                return externalContent2;
        }
    }

    private static ASN1Primitive getExternalContent(ASN1TaggedObject encoding2) {
        int tagClass = encoding2.getTagClass();
        int tagNo = encoding2.getTagNo();
        if (128 != tagClass) {
            throw new IllegalArgumentException("invalid tag: " + ASN1Util.getTagText(tagClass, tagNo));
        }
        switch (tagNo) {
            case 0:
                return encoding2.getExplicitBaseObject().toASN1Primitive();
            case 1:
                return ASN1OctetString.getInstance(encoding2, false);
            case 2:
                return ASN1BitString.getInstance(encoding2, false);
            default:
                throw new IllegalArgumentException("invalid tag: " + ASN1Util.getTagText(tagClass, tagNo));
        }
    }

    private static ASN1Primitive getObjFromSequence(ASN1Sequence sequence, int index) {
        if (sequence.size() > index) {
            return sequence.getObjectAt(index).toASN1Primitive();
        }
        throw new IllegalArgumentException("too few objects in input sequence");
    }
}
