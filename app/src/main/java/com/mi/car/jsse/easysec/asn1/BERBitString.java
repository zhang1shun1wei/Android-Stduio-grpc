package com.mi.car.jsse.easysec.asn1;

import java.io.IOException;

public class BERBitString extends ASN1BitString {
    private static final int DEFAULT_SEGMENT_LIMIT = 1000;
    private final ASN1BitString[] elements;
    private final int segmentLimit;

    static byte[] flattenBitStrings(ASN1BitString[] bitStrings) {
        int count = bitStrings.length;
        switch (count) {
            case 0:
                return new byte[]{0};
            case 1:
                return bitStrings[0].contents;
            default:
                int last = count - 1;
                int totalLength = 0;
                for (int i = 0; i < last; i++) {
                    byte[] elementContents = bitStrings[i].contents;
                    if (elementContents[0] != 0) {
                        throw new IllegalArgumentException("only the last nested bitstring can have padding");
                    }
                    totalLength += elementContents.length - 1;
                }
                byte[] lastElementContents = bitStrings[last].contents;
                byte padBits = lastElementContents[0];
                byte[] contents = new byte[(totalLength + lastElementContents.length)];
                contents[0] = padBits;
                int pos = 1;
                for (ASN1BitString aSN1BitString : bitStrings) {
                    byte[] elementContents2 = aSN1BitString.contents;
                    int length = elementContents2.length - 1;
                    System.arraycopy(elementContents2, 1, contents, pos, length);
                    pos += length;
                }
                return contents;
        }
    }

    public BERBitString(byte[] data) {
        this(data, 0);
    }

    public BERBitString(byte data, int padBits) {
        super(data, padBits);
        this.elements = null;
        this.segmentLimit = DEFAULT_SEGMENT_LIMIT;
    }

    public BERBitString(byte[] data, int padBits) {
        this(data, padBits, DEFAULT_SEGMENT_LIMIT);
    }

    public BERBitString(byte[] data, int padBits, int segmentLimit2) {
        super(data, padBits);
        this.elements = null;
        this.segmentLimit = segmentLimit2;
    }

    public BERBitString(ASN1Encodable obj) throws IOException {
        this(obj.toASN1Primitive().getEncoded(ASN1Encoding.DER), 0);
    }

    public BERBitString(ASN1BitString[] elements2) {
        this(elements2, (int) DEFAULT_SEGMENT_LIMIT);
    }

    public BERBitString(ASN1BitString[] elements2, int segmentLimit2) {
        super(flattenBitStrings(elements2), false);
        this.elements = elements2;
        this.segmentLimit = segmentLimit2;
    }

    BERBitString(byte[] contents, boolean check) {
        super(contents, check);
        this.elements = null;
        this.segmentLimit = DEFAULT_SEGMENT_LIMIT;
    }

    /* access modifiers changed from: package-private */
    @Override // com.mi.car.jsse.easysec.asn1.ASN1Primitive
    public boolean encodeConstructed() {
        return this.elements != null || this.contents.length > this.segmentLimit;
    }

    /* access modifiers changed from: package-private */
    @Override // com.mi.car.jsse.easysec.asn1.ASN1Primitive
    public int encodedLength(boolean withTag) throws IOException {
        if (!encodeConstructed()) {
            return DLBitString.encodedLength(withTag, this.contents.length);
        }
        int totalLength = withTag ? 4 : 3;
        if (this.elements != null) {
            for (int i = 0; i < this.elements.length; i++) {
                totalLength += this.elements[i].encodedLength(true);
            }
            return totalLength;
        } else if (this.contents.length < 2) {
            return totalLength;
        } else {
            int extraSegments = (this.contents.length - 2) / (this.segmentLimit - 1);
            return totalLength + (DLBitString.encodedLength(true, this.segmentLimit) * extraSegments) + DLBitString.encodedLength(true, this.contents.length - ((this.segmentLimit - 1) * extraSegments));
        }
    }

    /* access modifiers changed from: package-private */
    @Override // com.mi.car.jsse.easysec.asn1.ASN1Primitive
    public void encode(ASN1OutputStream out, boolean withTag) throws IOException {
        if (!encodeConstructed()) {
            DLBitString.encode(out, withTag, this.contents, 0, this.contents.length);
            return;
        }
        out.writeIdentifier(withTag, 35);
        out.write(128);
        if (this.elements != null) {
            out.writePrimitives(this.elements);
        } else if (this.contents.length >= 2) {
            byte pad = this.contents[0];
            int length = this.contents.length;
            int remaining = length - 1;
            int segmentLength = this.segmentLimit - 1;
            while (remaining > segmentLength) {
                DLBitString.encode(out, true, (byte) 0, this.contents, length - remaining, segmentLength);
                remaining -= segmentLength;
            }
            DLBitString.encode(out, true, pad, this.contents, length - remaining, remaining);
        }
        out.write(0);
        out.write(0);
    }
}
