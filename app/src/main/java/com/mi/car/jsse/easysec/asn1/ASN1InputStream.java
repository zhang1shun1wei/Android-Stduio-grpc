package com.mi.car.jsse.easysec.asn1;

import com.mi.car.jsse.easysec.iana.AEADAlgorithm;
import com.mi.car.jsse.easysec.util.io.Streams;
import java.io.ByteArrayInputStream;
import java.io.EOFException;
import java.io.FilterInputStream;
import java.io.IOException;
import java.io.InputStream;

public class ASN1InputStream extends FilterInputStream implements BERTags {
    private final boolean lazyEvaluate;
    private final int limit;
    private final byte[][] tmpBuffers;

    public ASN1InputStream(InputStream is) {
        this(is, StreamUtil.findLimit(is));
    }

    public ASN1InputStream(byte[] input) {
        this(new ByteArrayInputStream(input), input.length);
    }

    public ASN1InputStream(byte[] input, boolean lazyEvaluate2) {
        this(new ByteArrayInputStream(input), input.length, lazyEvaluate2);
    }

    public ASN1InputStream(InputStream input, int limit2) {
        this(input, limit2, false);
    }

    public ASN1InputStream(InputStream input, boolean lazyEvaluate2) {
        this(input, StreamUtil.findLimit(input), lazyEvaluate2);
    }

    public ASN1InputStream(InputStream input, int limit2, boolean lazyEvaluate2) {
        this(input, limit2, lazyEvaluate2, new byte[11][]);
    }

    private ASN1InputStream(InputStream input, int limit2, boolean lazyEvaluate2, byte[][] tmpBuffers2) {
        super(input);
        this.limit = limit2;
        this.lazyEvaluate = lazyEvaluate2;
        this.tmpBuffers = tmpBuffers2;
    }

    /* access modifiers changed from: package-private */
    public int getLimit() {
        return this.limit;
    }

    /* access modifiers changed from: protected */
    public int readLength() throws IOException {
        return readLength(this, this.limit, false);
    }

    /* access modifiers changed from: protected */
    public void readFully(byte[] bytes) throws IOException {
        if (Streams.readFully(this, bytes, 0, bytes.length) != bytes.length) {
            throw new EOFException("EOF encountered in middle of object");
        }
    }

    /* access modifiers changed from: protected */
    public ASN1Primitive buildObject(int tag, int tagNo, int length) throws IOException {
        boolean isConstructed = true;
        DefiniteLengthInputStream defIn = new DefiniteLengthInputStream(this, length, this.limit);
        if ((tag & BERTags.FLAGS) == 0) {
            return createPrimitiveDERObject(tagNo, defIn, this.tmpBuffers);
        }
        int tagClass = tag & BERTags.PRIVATE;
        if (tagClass != 0) {
            if ((tag & 32) == 0) {
                isConstructed = false;
            }
            return readTaggedObjectDL(tagClass, tagNo, isConstructed, defIn);
        }
        switch (tagNo) {
            case 3:
                return buildConstructedBitString(readVector(defIn));
            case 4:
                return buildConstructedOctetString(readVector(defIn));
            case 8:
                return DLFactory.createSequence(readVector(defIn)).toASN1External();
            case 16:
                if (defIn.getRemaining() < 1) {
                    return DLFactory.EMPTY_SEQUENCE;
                }
                if (this.lazyEvaluate) {
                    return new LazyEncodedSequence(defIn.toByteArray());
                }
                return DLFactory.createSequence(readVector(defIn));
            case 17:
                return DLFactory.createSet(readVector(defIn));
            default:
                throw new IOException("unknown tag " + tagNo + " encountered");
        }
    }

    public ASN1Primitive readObject() throws IOException {
        int tag = read();
        if (tag > 0) {
            int tagNo = readTagNumber(this, tag);
            int length = readLength();
            if (length >= 0) {
                try {
                    return buildObject(tag, tagNo, length);
                } catch (IllegalArgumentException e) {
                    throw new ASN1Exception("corrupted stream detected", e);
                }
            } else if ((tag & 32) == 0) {
                throw new IOException("indefinite-length primitive encoding encountered");
            } else {
                ASN1StreamParser sp = new ASN1StreamParser(new IndefiniteLengthInputStream(this, this.limit), this.limit, this.tmpBuffers);
                int tagClass = tag & BERTags.PRIVATE;
                if (tagClass != 0) {
                    return sp.loadTaggedIL(tagClass, tagNo);
                }
                switch (tagNo) {
                    case 3:
                        return BERBitStringParser.parse(sp);
                    case 4:
                        return BEROctetStringParser.parse(sp);
                    case 8:
                        return DERExternalParser.parse(sp);
                    case 16:
                        return BERSequenceParser.parse(sp);
                    case 17:
                        return BERSetParser.parse(sp);
                    default:
                        throw new IOException("unknown BER object encountered");
                }
            }
        } else if (tag != 0) {
            return null;
        } else {
            throw new IOException("unexpected end-of-contents marker");
        }
    }

    /* access modifiers changed from: package-private */
    public ASN1BitString buildConstructedBitString(ASN1EncodableVector contentsElements) throws IOException {
        ASN1BitString[] strings = new ASN1BitString[contentsElements.size()];
        for (int i = 0; i != strings.length; i++) {
            ASN1Encodable asn1Obj = contentsElements.get(i);
            if (asn1Obj instanceof ASN1BitString) {
                strings[i] = (ASN1BitString) asn1Obj;
            } else {
                throw new ASN1Exception("unknown object encountered in constructed BIT STRING: " + asn1Obj.getClass());
            }
        }
        return new BERBitString(strings);
    }

    /* access modifiers changed from: package-private */
    public ASN1OctetString buildConstructedOctetString(ASN1EncodableVector contentsElements) throws IOException {
        ASN1OctetString[] strings = new ASN1OctetString[contentsElements.size()];
        for (int i = 0; i != strings.length; i++) {
            ASN1Encodable asn1Obj = contentsElements.get(i);
            if (asn1Obj instanceof ASN1OctetString) {
                strings[i] = (ASN1OctetString) asn1Obj;
            } else {
                throw new ASN1Exception("unknown object encountered in constructed OCTET STRING: " + asn1Obj.getClass());
            }
        }
        return new BEROctetString(strings);
    }

    /* access modifiers changed from: package-private */
    public ASN1Primitive readTaggedObjectDL(int tagClass, int tagNo, boolean constructed, DefiniteLengthInputStream defIn) throws IOException {
        if (!constructed) {
            return ASN1TaggedObject.createPrimitive(tagClass, tagNo, defIn.toByteArray());
        }
        return ASN1TaggedObject.createConstructedDL(tagClass, tagNo, readVector(defIn));
    }

    /* access modifiers changed from: package-private */
    public ASN1EncodableVector readVector() throws IOException {
        ASN1Primitive p = readObject();
        if (p == null) {
            return new ASN1EncodableVector(0);
        }
        ASN1EncodableVector v = new ASN1EncodableVector();
        do {
            v.add(p);
            p = readObject();
        } while (p != null);
        return v;
    }

    /* access modifiers changed from: package-private */
    public ASN1EncodableVector readVector(DefiniteLengthInputStream defIn) throws IOException {
        int remaining = defIn.getRemaining();
        if (remaining < 1) {
            return new ASN1EncodableVector(0);
        }
        return new ASN1InputStream(defIn, remaining, this.lazyEvaluate, this.tmpBuffers).readVector();
    }

    static int readTagNumber(InputStream s, int tag) throws IOException {
        int tagNo = tag & 31;
        if (tagNo == 31) {
            int b = s.read();
            if (b >= 31) {
                tagNo = b & 127;
                if (tagNo == 0) {
                    throw new IOException("corrupted stream - invalid high tag number found");
                }
                while ((b & 128) != 0) {
                    if ((tagNo >>> 24) != 0) {
                        throw new IOException("Tag number more than 31 bits");
                    }
                    int tagNo2 = tagNo << 7;
                    b = s.read();
                    if (b < 0) {
                        throw new EOFException("EOF found inside tag value.");
                    }
                    tagNo = tagNo2 | (b & 127);
                }
            } else if (b < 0) {
                throw new EOFException("EOF found inside tag value.");
            } else {
                throw new IOException("corrupted stream - high tag number < 31 found");
            }
        }
        return tagNo;
    }

    static int readLength(InputStream s, int limit2, boolean isParsing) throws IOException {
        int length = s.read();
        if ((length >>> 7) == 0) {
            return length;
        }
        if (128 == length) {
            return -1;
        }
        if (length < 0) {
            throw new EOFException("EOF found when length expected");
        } else if (255 == length) {
            throw new IOException("invalid long form definite-length 0xFF");
        } else {
            int octetsCount = length & 127;
            int octetsPos = 0;
            int length2 = 0;
            do {
                int octet = s.read();
                if (octet < 0) {
                    throw new EOFException("EOF found reading length");
                } else if ((length2 >>> 23) != 0) {
                    throw new IOException("long form definite-length more than 31 bits");
                } else {
                    length2 = (length2 << 8) + octet;
                    octetsPos++;
                }
            } while (octetsPos < octetsCount);
            if (length2 < limit2 || isParsing) {
                return length2;
            }
            throw new IOException("corrupted stream - out of bounds length found: " + length2 + " >= " + limit2);
        }
    }

    private static byte[] getBuffer(DefiniteLengthInputStream defIn, byte[][] tmpBuffers2) throws IOException {
        int len = defIn.getRemaining();
        if (len >= tmpBuffers2.length) {
            return defIn.toByteArray();
        }
        byte[] buf = tmpBuffers2[len];
        if (buf == null) {
            buf = new byte[len];
            tmpBuffers2[len] = buf;
        }
        defIn.readAllIntoByteArray(buf);
        return buf;
    }

    private static char[] getBMPCharBuffer(DefiniteLengthInputStream defIn) throws IOException {
        int stringPos;
        int remainingBytes = defIn.getRemaining();
        if ((remainingBytes & 1) != 0) {
            throw new IOException("malformed BMPString encoding encountered");
        }
        char[] string = new char[(remainingBytes / 2)];
        int stringPos2 = 0;
        byte[] buf = new byte[8];
        while (remainingBytes >= 8) {
            if (Streams.readFully(defIn, buf, 0, 8) != 8) {
                throw new EOFException("EOF encountered in middle of BMPString");
            }
            string[stringPos2] = (char) ((buf[0] << 8) | (buf[1] & 255));
            string[stringPos2 + 1] = (char) ((buf[2] << 8) | (buf[3] & 255));
            string[stringPos2 + 2] = (char) ((buf[4] << 8) | (buf[5] & 255));
            string[stringPos2 + 3] = (char) ((buf[6] << 8) | (buf[7] & 255));
            stringPos2 += 4;
            remainingBytes -= 8;
        }
        if (remainingBytes > 0) {
            if (Streams.readFully(defIn, buf, 0, remainingBytes) != remainingBytes) {
                throw new EOFException("EOF encountered in middle of BMPString");
            }
            int bufPos = 0;
            while (true) {
                int bufPos2 = bufPos + 1;
                bufPos = bufPos2 + 1;
                stringPos = stringPos2 + 1;
                string[stringPos2] = (char) ((buf[bufPos] << 8) | (buf[bufPos2] & 255));
                if (bufPos >= remainingBytes) {
                    break;
                }
                stringPos2 = stringPos;
            }
            stringPos2 = stringPos;
        }
        if (defIn.getRemaining() == 0 && string.length == stringPos2) {
            return string;
        }
        throw new IllegalStateException();
    }

    static ASN1Primitive createPrimitiveDERObject(int tagNo, DefiniteLengthInputStream defIn, byte[][] tmpBuffers2) throws IOException {
        switch (tagNo) {
            case 1:
                return ASN1Boolean.createPrimitive(getBuffer(defIn, tmpBuffers2));
            case 2:
                return ASN1Integer.createPrimitive(defIn.toByteArray());
            case 3:
                return ASN1BitString.createPrimitive(defIn.toByteArray());
            case 4:
                return ASN1OctetString.createPrimitive(defIn.toByteArray());
            case 5:
                return ASN1Null.createPrimitive(defIn.toByteArray());
            case 6:
                return ASN1ObjectIdentifier.createPrimitive(getBuffer(defIn, tmpBuffers2), true);
            case 7:
                return ASN1ObjectDescriptor.createPrimitive(defIn.toByteArray());
            case 8:
            case 9:
            case 11:
            case 14:
            case AEADAlgorithm.AEAD_AES_SIV_CMAC_256 /*{ENCODED_INT: 15}*/:
            case 16:
            case 17:
            case 29:
            default:
                throw new IOException("unknown tag " + tagNo + " encountered");
            case 10:
                return ASN1Enumerated.createPrimitive(getBuffer(defIn, tmpBuffers2), true);
            case 12:
                return ASN1UTF8String.createPrimitive(defIn.toByteArray());
            case 13:
                return ASN1RelativeOID.createPrimitive(defIn.toByteArray(), false);
            case 18:
                return ASN1NumericString.createPrimitive(defIn.toByteArray());
            case 19:
                return ASN1PrintableString.createPrimitive(defIn.toByteArray());
            case 20:
                return ASN1T61String.createPrimitive(defIn.toByteArray());
            case 21:
                return ASN1VideotexString.createPrimitive(defIn.toByteArray());
            case 22:
                return ASN1IA5String.createPrimitive(defIn.toByteArray());
            case 23:
                return ASN1UTCTime.createPrimitive(defIn.toByteArray());
            case 24:
                return ASN1GeneralizedTime.createPrimitive(defIn.toByteArray());
            case 25:
                return ASN1GraphicString.createPrimitive(defIn.toByteArray());
            case 26:
                return ASN1VisibleString.createPrimitive(defIn.toByteArray());
            case 27:
                return ASN1GeneralString.createPrimitive(defIn.toByteArray());
            case 28:
                return ASN1UniversalString.createPrimitive(defIn.toByteArray());
            case 30:
                return ASN1BMPString.createPrimitive(getBMPCharBuffer(defIn));
        }
    }
}
