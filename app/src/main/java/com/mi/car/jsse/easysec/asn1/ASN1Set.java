package com.mi.car.jsse.easysec.asn1;

import com.mi.car.jsse.easysec.util.Arrays;
import com.mi.car.jsse.easysec.util.Iterable;
import java.io.IOException;
import java.util.Enumeration;
import java.util.Iterator;
import java.util.NoSuchElementException;

public abstract class ASN1Set extends ASN1Primitive implements Iterable<ASN1Encodable> {
    static final ASN1UniversalType TYPE = new ASN1UniversalType(ASN1Set.class, 17) {
        /* class com.mi.car.jsse.easysec.asn1.ASN1Set.AnonymousClass1 */

        /* access modifiers changed from: package-private */
        @Override // com.mi.car.jsse.easysec.asn1.ASN1UniversalType
        public ASN1Primitive fromImplicitConstructed(ASN1Sequence sequence) {
            return sequence.toASN1Set();
        }
    };
    protected final ASN1Encodable[] elements;
    protected final boolean isSorted;

    public static ASN1Set getInstance(Object obj) {
        if (obj == null || (obj instanceof ASN1Set)) {
            return (ASN1Set) obj;
        }
        if (obj instanceof ASN1Encodable) {
            ASN1Primitive primitive = ((ASN1Encodable) obj).toASN1Primitive();
            if (primitive instanceof ASN1Set) {
                return (ASN1Set) primitive;
            }
        } else if (obj instanceof byte[]) {
            try {
                return (ASN1Set) TYPE.fromByteArray((byte[]) obj);
            } catch (IOException e) {
                throw new IllegalArgumentException("failed to construct set from byte[]: " + e.getMessage());
            }
        }
        throw new IllegalArgumentException("unknown object in getInstance: " + obj.getClass().getName());
    }

    public static ASN1Set getInstance(ASN1TaggedObject taggedObject, boolean explicit) {
        return (ASN1Set) TYPE.getContextInstance(taggedObject, explicit);
    }

    protected ASN1Set() {
        this.elements = ASN1EncodableVector.EMPTY_ELEMENTS;
        this.isSorted = true;
    }

    protected ASN1Set(ASN1Encodable element) {
        if (element == null) {
            throw new NullPointerException("'element' cannot be null");
        }
        this.elements = new ASN1Encodable[]{element};
        this.isSorted = true;
    }

    protected ASN1Set(ASN1EncodableVector elementVector, boolean doSort) {
        ASN1Encodable[] tmp;
        if (elementVector == null) {
            throw new NullPointerException("'elementVector' cannot be null");
        }
        if (!doSort || elementVector.size() < 2) {
            tmp = elementVector.takeElements();
        } else {
            tmp = elementVector.copyElements();
            sort(tmp);
        }
        this.elements = tmp;
        this.isSorted = doSort || tmp.length < 2;
    }

    protected ASN1Set(ASN1Encodable[] elements2, boolean doSort) {
        if (Arrays.isNullOrContainsNull(elements2)) {
            throw new NullPointerException("'elements' cannot be null, or contain null");
        }
        ASN1Encodable[] tmp = ASN1EncodableVector.cloneElements(elements2);
        if (doSort && tmp.length >= 2) {
            sort(tmp);
        }
        this.elements = tmp;
        this.isSorted = doSort || tmp.length < 2;
    }

    ASN1Set(boolean isSorted2, ASN1Encodable[] elements2) {
        this.elements = elements2;
        this.isSorted = isSorted2 || elements2.length < 2;
    }

    public Enumeration getObjects() {
        return new Enumeration() {
            /* class com.mi.car.jsse.easysec.asn1.ASN1Set.AnonymousClass2 */
            private int pos = 0;

            public boolean hasMoreElements() {
                return this.pos < ASN1Set.this.elements.length;
            }

            @Override // java.util.Enumeration
            public Object nextElement() {
                if (this.pos < ASN1Set.this.elements.length) {
                    ASN1Encodable[] aSN1EncodableArr = ASN1Set.this.elements;
                    int i = this.pos;
                    this.pos = i + 1;
                    return aSN1EncodableArr[i];
                }
                throw new NoSuchElementException();
            }
        };
    }

    public ASN1Encodable getObjectAt(int index) {
        return this.elements[index];
    }

    public int size() {
        return this.elements.length;
    }

    public ASN1Encodable[] toArray() {
        return ASN1EncodableVector.cloneElements(this.elements);
    }

    public ASN1SetParser parser() {
        final int count = size();
        return new ASN1SetParser() {
            /* class com.mi.car.jsse.easysec.asn1.ASN1Set.AnonymousClass3 */
            private int pos = 0;

            @Override // com.mi.car.jsse.easysec.asn1.ASN1SetParser
            public ASN1Encodable readObject() throws IOException {
                if (count == this.pos) {
                    return null;
                }
                ASN1Encodable[] aSN1EncodableArr = ASN1Set.this.elements;
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
                return ASN1Set.this;
            }

            @Override // com.mi.car.jsse.easysec.asn1.ASN1Encodable
            public ASN1Primitive toASN1Primitive() {
                return ASN1Set.this;
            }
        };
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
            hc += this.elements[i].toASN1Primitive().hashCode();
        }
    }

    /* access modifiers changed from: package-private */
    @Override // com.mi.car.jsse.easysec.asn1.ASN1Primitive
    public ASN1Primitive toDERObject() {
        ASN1Encodable[] tmp;
        if (this.isSorted) {
            tmp = this.elements;
        } else {
            tmp = (ASN1Encodable[]) this.elements.clone();
            sort(tmp);
        }
        return new DERSet(true, tmp);
    }

    /* access modifiers changed from: package-private */
    @Override // com.mi.car.jsse.easysec.asn1.ASN1Primitive
    public ASN1Primitive toDLObject() {
        return new DLSet(this.isSorted, this.elements);
    }

    /* access modifiers changed from: package-private */
    @Override // com.mi.car.jsse.easysec.asn1.ASN1Primitive
    public boolean asn1Equals(ASN1Primitive other) {
        if (!(other instanceof ASN1Set)) {
            return false;
        }
        ASN1Set that = (ASN1Set) other;
        int count = size();
        if (that.size() != count) {
            return false;
        }
        DERSet dis = (DERSet) toDERObject();
        DERSet dat = (DERSet) that.toDERObject();
        for (int i = 0; i < count; i++) {
            ASN1Primitive p1 = dis.elements[i].toASN1Primitive();
            ASN1Primitive p2 = dat.elements[i].toASN1Primitive();
            if (!(p1 == p2 || p1.asn1Equals(p2))) {
                return false;
            }
        }
        return true;
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
        return new Arrays.Iterator(toArray());
    }

    private static byte[] getDEREncoded(ASN1Encodable obj) {
        try {
            return obj.toASN1Primitive().getEncoded(ASN1Encoding.DER);
        } catch (IOException e) {
            throw new IllegalArgumentException("cannot encode object added to SET");
        }
    }

    private static boolean lessThanOrEqual(byte[] a, byte[] b) {
        int a0 = a[0] & -33;
        int b0 = b[0] & -33;
        if (a0 != b0) {
            return a0 < b0;
        }
        int last = Math.min(a.length, b.length) - 1;
        for (int i = 1; i < last; i++) {
            if (a[i] != b[i]) {
                return (a[i] & 255) < (b[i] & 255);
            }
        }
        return (a[last] & 255) <= (b[last] & 255);
    }

    private static void sort(ASN1Encodable[] t) {
        int count = t.length;
        if (count >= 2) {
            ASN1Encodable eh = t[0];
            ASN1Encodable ei = t[1];
            byte[] bh = getDEREncoded(eh);
            byte[] bi = getDEREncoded(ei);
            if (lessThanOrEqual(bi, bh)) {
                ei = eh;
                eh = ei;
                bi = bh;
                bh = bi;
            }
            for (int i = 2; i < count; i++) {
                ASN1Encodable e2 = t[i];
                byte[] b2 = getDEREncoded(e2);
                if (lessThanOrEqual(bi, b2)) {
                    t[i - 2] = eh;
                    eh = ei;
                    bh = bi;
                    ei = e2;
                    bi = b2;
                } else if (lessThanOrEqual(bh, b2)) {
                    t[i - 2] = eh;
                    eh = e2;
                    bh = b2;
                } else {
                    int j = i - 1;
                    while (true) {
                        j--;
                        if (j <= 0) {
                            break;
                        }
                        ASN1Encodable e1 = t[j - 1];
                        if (lessThanOrEqual(getDEREncoded(e1), b2)) {
                            break;
                        }
                        t[j] = e1;
                    }
                    t[j] = e2;
                }
            }
            t[count - 2] = eh;
            t[count - 1] = ei;
        }
    }
}
