package com.mi.car.jsse.easysec.asn1;

import java.io.IOException;
import java.util.Enumeration;
import java.util.NoSuchElementException;

public class BEROctetString extends ASN1OctetString {
    private static final int DEFAULT_SEGMENT_LIMIT = 1000;
    private final ASN1OctetString[] elements;
    private final int segmentLimit;

    static byte[] flattenOctetStrings(ASN1OctetString[] octetStrings) {
        int count = octetStrings.length;
        switch (count) {
            case 0:
                return EMPTY_OCTETS;
            case 1:
                return octetStrings[0].string;
            default:
                int totalOctets = 0;
                for (ASN1OctetString aSN1OctetString : octetStrings) {
                    totalOctets += aSN1OctetString.string.length;
                }
                byte[] string = new byte[totalOctets];
                int pos = 0;
                for (ASN1OctetString aSN1OctetString2 : octetStrings) {
                    byte[] octets = aSN1OctetString2.string;
                    System.arraycopy(octets, 0, string, pos, octets.length);
                    pos += octets.length;
                }
                return string;
        }
    }

    public BEROctetString(byte[] string) {
        this(string, (int) DEFAULT_SEGMENT_LIMIT);
    }

    public BEROctetString(ASN1OctetString[] elements2) {
        this(elements2, (int) DEFAULT_SEGMENT_LIMIT);
    }

    public BEROctetString(byte[] string, int segmentLimit2) {
        this(string, null, segmentLimit2);
    }

    public BEROctetString(ASN1OctetString[] elements2, int segmentLimit2) {
        this(flattenOctetStrings(elements2), elements2, segmentLimit2);
    }

    private BEROctetString(byte[] string, ASN1OctetString[] elements2, int segmentLimit2) {
        super(string);
        this.elements = elements2;
        this.segmentLimit = segmentLimit2;
    }

    public Enumeration getObjects() {
        return this.elements == null ? new Enumeration() {
            /* class com.mi.car.jsse.easysec.asn1.BEROctetString.AnonymousClass1 */
            int pos = 0;

            public boolean hasMoreElements() {
                return this.pos < BEROctetString.this.string.length;
            }

            @Override // java.util.Enumeration
            public Object nextElement() {
                if (this.pos < BEROctetString.this.string.length) {
                    int length = Math.min(BEROctetString.this.string.length - this.pos, BEROctetString.this.segmentLimit);
                    byte[] segment = new byte[length];
                    System.arraycopy(BEROctetString.this.string, this.pos, segment, 0, length);
                    this.pos += length;
                    return new DEROctetString(segment);
                }
                throw new NoSuchElementException();
            }
        } : new Enumeration() {
            /* class com.mi.car.jsse.easysec.asn1.BEROctetString.AnonymousClass2 */
            int counter = 0;

            public boolean hasMoreElements() {
                return this.counter < BEROctetString.this.elements.length;
            }

            @Override // java.util.Enumeration
            public Object nextElement() {
                if (this.counter < BEROctetString.this.elements.length) {
                    ASN1OctetString[] aSN1OctetStringArr = BEROctetString.this.elements;
                    int i = this.counter;
                    this.counter = i + 1;
                    return aSN1OctetStringArr[i];
                }
                throw new NoSuchElementException();
            }
        };
    }

    /* access modifiers changed from: package-private */
    @Override // com.mi.car.jsse.easysec.asn1.ASN1Primitive
    public boolean encodeConstructed() {
        return this.elements != null || this.string.length > this.segmentLimit;
    }

    /* access modifiers changed from: package-private */
    @Override // com.mi.car.jsse.easysec.asn1.ASN1Primitive
    public int encodedLength(boolean withTag) throws IOException {
        if (!encodeConstructed()) {
            return DEROctetString.encodedLength(withTag, this.string.length);
        }
        int totalLength = withTag ? 4 : 3;
        if (this.elements != null) {
            for (int i = 0; i < this.elements.length; i++) {
                totalLength += this.elements[i].encodedLength(true);
            }
            return totalLength;
        }
        int fullSegments = this.string.length / this.segmentLimit;
        int totalLength2 = totalLength + (DEROctetString.encodedLength(true, this.segmentLimit) * fullSegments);
        int lastSegmentLength = this.string.length - (this.segmentLimit * fullSegments);
        if (lastSegmentLength > 0) {
            return totalLength2 + DEROctetString.encodedLength(true, lastSegmentLength);
        }
        return totalLength2;
    }

    /* access modifiers changed from: package-private */
    @Override // com.mi.car.jsse.easysec.asn1.ASN1Primitive
    public void encode(ASN1OutputStream out, boolean withTag) throws IOException {
        if (!encodeConstructed()) {
            DEROctetString.encode(out, withTag, this.string, 0, this.string.length);
            return;
        }
        out.writeIdentifier(withTag, 36);
        out.write(128);
        if (this.elements != null) {
            out.writePrimitives(this.elements);
        } else {
            int pos = 0;
            while (pos < this.string.length) {
                int segmentLength = Math.min(this.string.length - pos, this.segmentLimit);
                DEROctetString.encode(out, true, this.string, pos, segmentLength);
                pos += segmentLength;
            }
        }
        out.write(0);
        out.write(0);
    }
}
