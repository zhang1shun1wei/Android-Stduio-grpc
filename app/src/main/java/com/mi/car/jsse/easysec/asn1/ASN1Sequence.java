package com.mi.car.jsse.easysec.asn1;

import com.mi.car.jsse.easysec.util.Arrays;
import com.mi.car.jsse.easysec.util.Iterable;
import java.io.IOException;
import java.util.Enumeration;
import java.util.Iterator;
import java.util.NoSuchElementException;

public abstract class ASN1Sequence extends ASN1Primitive implements Iterable<ASN1Encodable> {
    static final ASN1UniversalType TYPE = new ASN1UniversalType(ASN1Sequence.class, 16) {
        /* class com.mi.car.jsse.easysec.asn1.ASN1Sequence.AnonymousClass1 */

        /* access modifiers changed from: package-private */
        @Override // com.mi.car.jsse.easysec.asn1.ASN1UniversalType
        public ASN1Primitive fromImplicitConstructed(ASN1Sequence sequence) {
            return sequence;
        }
    };
    ASN1Encodable[] elements;

    /* access modifiers changed from: package-private */
    public abstract ASN1BitString toASN1BitString();

    /* access modifiers changed from: package-private */
    public abstract ASN1External toASN1External();

    /* access modifiers changed from: package-private */
    public abstract ASN1OctetString toASN1OctetString();

    /* access modifiers changed from: package-private */
    public abstract ASN1Set toASN1Set();

    public static ASN1Sequence getInstance(Object obj) {
        if (obj == null || (obj instanceof ASN1Sequence)) {
            return (ASN1Sequence) obj;
        }
        if (obj instanceof ASN1Encodable) {
            ASN1Primitive primitive = ((ASN1Encodable) obj).toASN1Primitive();
            if (primitive instanceof ASN1Sequence) {
                return (ASN1Sequence) primitive;
            }
        } else if (obj instanceof byte[]) {
            try {
                return (ASN1Sequence) TYPE.fromByteArray((byte[]) obj);
            } catch (IOException e) {
                throw new IllegalArgumentException("failed to construct sequence from byte[]: " + e.getMessage());
            }
        }
        throw new IllegalArgumentException("unknown object in getInstance: " + obj.getClass().getName());
    }

    public static ASN1Sequence getInstance(ASN1TaggedObject taggedObject, boolean explicit) {
        return (ASN1Sequence) TYPE.getContextInstance(taggedObject, explicit);
    }

    protected ASN1Sequence() {
        this.elements = ASN1EncodableVector.EMPTY_ELEMENTS;
    }

    protected ASN1Sequence(ASN1Encodable element) {
        if (element == null) {
            throw new NullPointerException("'element' cannot be null");
        }
        this.elements = new ASN1Encodable[]{element};
    }

    protected ASN1Sequence(ASN1EncodableVector elementVector) {
        if (elementVector == null) {
            throw new NullPointerException("'elementVector' cannot be null");
        }
        this.elements = elementVector.takeElements();
    }

    protected ASN1Sequence(ASN1Encodable[] elements2) {
        if (Arrays.isNullOrContainsNull(elements2)) {
            throw new NullPointerException("'elements' cannot be null, or contain null");
        }
        this.elements = ASN1EncodableVector.cloneElements(elements2);
    }

    ASN1Sequence(ASN1Encodable[] elements2, boolean clone) {
        this.elements = clone ? ASN1EncodableVector.cloneElements(elements2) : elements2;
    }

    public ASN1Encodable[] toArray() {
        return ASN1EncodableVector.cloneElements(this.elements);
    }

    /* access modifiers changed from: package-private */
    public ASN1Encodable[] toArrayInternal() {
        return this.elements;
    }

    public Enumeration getObjects() {
        return new Enumeration() {
            /* class com.mi.car.jsse.easysec.asn1.ASN1Sequence.AnonymousClass2 */
            private int pos = 0;

            public boolean hasMoreElements() {
                return this.pos < ASN1Sequence.this.elements.length;
            }

            @Override // java.util.Enumeration
            public Object nextElement() {
                if (this.pos < ASN1Sequence.this.elements.length) {
                    ASN1Encodable[] aSN1EncodableArr = ASN1Sequence.this.elements;
                    int i = this.pos;
                    this.pos = i + 1;
                    return aSN1EncodableArr[i];
                }
                throw new NoSuchElementException();
            }
        };
    }

    public ASN1SequenceParser parser() {
        final int count = size();
        return new ASN1SequenceParser() {
            /* class com.mi.car.jsse.easysec.asn1.ASN1Sequence.AnonymousClass3 */
            private int pos = 0;

            @Override // com.mi.car.jsse.easysec.asn1.ASN1SequenceParser
            public ASN1Encodable readObject() throws IOException {
                if (count == this.pos) {
                    return null;
                }
                ASN1Encodable[] aSN1EncodableArr = ASN1Sequence.this.elements;
                int i = this.pos;
                this.pos = i + 1;
                ASN1Encodable obj = aSN1EncodableArr[i];
                if (obj instanceof ASN1Sequence) {
                    return ((ASN1Sequence) obj).parser();
                }
                if (obj instanceof ASN1Set) {
                    return ((ASN1Set) obj).parser();
                }
                return obj;
            }

            @Override // com.mi.car.jsse.easysec.asn1.InMemoryRepresentable
            public ASN1Primitive getLoadedObject() {
                return ASN1Sequence.this;
            }

            @Override // com.mi.car.jsse.easysec.asn1.ASN1Encodable
            public ASN1Primitive toASN1Primitive() {
                return ASN1Sequence.this;
            }
        };
    }

    public ASN1Encodable getObjectAt(int index) {
        return this.elements[index];
    }

    public int size() {
        return this.elements.length;
    }

    @Override // com.mi.car.jsse.easysec.asn1.ASN1Object, com.mi.car.jsse.easysec.asn1.ASN1Primitive
    public int hashCode() {
        int i = this.elements.length;
        int hc = i + 1;
        while (true) {
            i--;
            if (i < 0) {
                return hc;
            }
            hc = (hc * 257) ^ this.elements[i].toASN1Primitive().hashCode();
        }
    }

    /* access modifiers changed from: package-private */
    @Override // com.mi.car.jsse.easysec.asn1.ASN1Primitive
    public boolean asn1Equals(ASN1Primitive other) {
        if (!(other instanceof ASN1Sequence)) {
            return false;
        }
        ASN1Sequence that = (ASN1Sequence) other;
        int count = size();
        if (that.size() != count) {
            return false;
        }
        for (int i = 0; i < count; i++) {
            ASN1Primitive p1 = this.elements[i].toASN1Primitive();
            ASN1Primitive p2 = that.elements[i].toASN1Primitive();
            if (!(p1 == p2 || p1.asn1Equals(p2))) {
                return false;
            }
        }
        return true;
    }

    /* access modifiers changed from: package-private */
    @Override // com.mi.car.jsse.easysec.asn1.ASN1Primitive
    public ASN1Primitive toDERObject() {
        return new DERSequence(this.elements, false);
    }

    /* access modifiers changed from: package-private */
    @Override // com.mi.car.jsse.easysec.asn1.ASN1Primitive
    public ASN1Primitive toDLObject() {
        return new DLSequence(this.elements, false);
    }

    /* access modifiers changed from: package-private */
    @Override // com.mi.car.jsse.easysec.asn1.ASN1Primitive
    public boolean encodeConstructed() {
        return true;
    }

    public String toString() {
        int count = size();
        if (count == 0) {
            return "[]";
        }
        StringBuffer sb = new StringBuffer();
        sb.append('[');
        int i = 0;
        while (true) {
            sb.append(this.elements[i]);
            i++;
            if (i >= count) {
                sb.append(']');
                return sb.toString();
            }
            sb.append(", ");
        }
    }

    @Override // com.mi.car.jsse.easysec.util.Iterable, java.lang.Iterable
    public Iterator<ASN1Encodable> iterator() {
        return new Arrays.Iterator(this.elements);
    }

    /* access modifiers changed from: package-private */
    public ASN1BitString[] getConstructedBitStrings() {
        int count = size();
        ASN1BitString[] bitStrings = new ASN1BitString[count];
        for (int i = 0; i < count; i++) {
            bitStrings[i] = ASN1BitString.getInstance(this.elements[i]);
        }
        return bitStrings;
    }

    /* access modifiers changed from: package-private */
    public ASN1OctetString[] getConstructedOctetStrings() {
        int count = size();
        ASN1OctetString[] octetStrings = new ASN1OctetString[count];
        for (int i = 0; i < count; i++) {
            octetStrings[i] = ASN1OctetString.getInstance(this.elements[i]);
        }
        return octetStrings;
    }
}
