package com.mi.car.jsse.easysec.asn1;

import java.io.IOException;
import java.io.InputStream;

public class DLBitStringParser implements ASN1BitStringParser {
    private int padBits = 0;
    private final DefiniteLengthInputStream stream;

    DLBitStringParser(DefiniteLengthInputStream stream2) {
        this.stream = stream2;
    }

    @Override // com.mi.car.jsse.easysec.asn1.ASN1BitStringParser
    public InputStream getBitStream() throws IOException {
        return getBitStream(false);
    }

    @Override // com.mi.car.jsse.easysec.asn1.ASN1BitStringParser
    public InputStream getOctetStream() throws IOException {
        return getBitStream(true);
    }

    @Override // com.mi.car.jsse.easysec.asn1.ASN1BitStringParser
    public int getPadBits() {
        return this.padBits;
    }

    @Override // com.mi.car.jsse.easysec.asn1.InMemoryRepresentable
    public ASN1Primitive getLoadedObject() throws IOException {
        return ASN1BitString.createPrimitive(this.stream.toByteArray());
    }

    @Override // com.mi.car.jsse.easysec.asn1.ASN1Encodable
    public ASN1Primitive toASN1Primitive() {
        try {
            return getLoadedObject();
        } catch (IOException e) {
            throw new ASN1ParsingException("IOException converting stream to byte array: " + e.getMessage(), e);
        }
    }

    private InputStream getBitStream(boolean octetAligned) throws IOException {
        int length = this.stream.getRemaining();
        if (length < 1) {
            throw new IllegalStateException("content octets cannot be empty");
        }
        this.padBits = this.stream.read();
        if (this.padBits > 0) {
            if (length < 2) {
                throw new IllegalStateException("zero length data with non-zero pad bits");
            } else if (this.padBits > 7) {
                throw new IllegalStateException("pad bits cannot be greater than 7 or less than 0");
            } else if (octetAligned) {
                throw new IOException("expected octet-aligned bitstring, but found padBits: " + this.padBits);
            }
        }
        return this.stream;
    }
}
