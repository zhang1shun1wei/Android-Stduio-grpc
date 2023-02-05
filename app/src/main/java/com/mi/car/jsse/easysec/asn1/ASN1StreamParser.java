package com.mi.car.jsse.easysec.asn1;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;

public class ASN1StreamParser {
    private final InputStream _in;
    private final int _limit;
    private final byte[][] tmpBuffers;

    public ASN1StreamParser(InputStream in) {
        this(in, StreamUtil.findLimit(in));
    }

    public ASN1StreamParser(byte[] encoding) {
        this(new ByteArrayInputStream(encoding), encoding.length);
    }

    public ASN1StreamParser(InputStream in, int limit) {
        this(in, limit, new byte[11][]);
    }

    ASN1StreamParser(InputStream in, int limit, byte[][] tmpBuffers2) {
        this._in = in;
        this._limit = limit;
        this.tmpBuffers = tmpBuffers2;
    }

    public ASN1Encodable readObject() throws IOException {
        int tagHdr = this._in.read();
        if (tagHdr < 0) {
            return null;
        }
        return implParseObject(tagHdr);
    }

    /* access modifiers changed from: package-private */
    public ASN1Encodable implParseObject(int tagHdr) throws IOException {
        boolean z;
        boolean isConstructed;
        set00Check(false);
        int tagNo = ASN1InputStream.readTagNumber(this._in, tagHdr);
        InputStream inputStream = this._in;
        int i = this._limit;
        if (tagNo == 3 || tagNo == 4 || tagNo == 16 || tagNo == 17 || tagNo == 8) {
            z = true;
        } else {
            z = false;
        }
        int length = ASN1InputStream.readLength(inputStream, i, z);
        if (length >= 0) {
            DefiniteLengthInputStream defIn = new DefiniteLengthInputStream(this._in, length, this._limit);
            if ((tagHdr & BERTags.FLAGS) == 0) {
                return parseImplicitPrimitive(tagNo, defIn);
            }
            ASN1StreamParser sp = new ASN1StreamParser(defIn, defIn.getLimit(), this.tmpBuffers);
            int tagClass = tagHdr & BERTags.PRIVATE;
            if (tagClass == 0) {
                return sp.parseImplicitConstructedDL(tagNo);
            }
            if ((tagHdr & 32) != 0) {
                isConstructed = true;
            } else {
                isConstructed = false;
            }
            if (64 == tagClass) {
                return (DLApplicationSpecific) sp.loadTaggedDL(tagClass, tagNo, isConstructed);
            }
            return new DLTaggedObjectParser(tagClass, tagNo, isConstructed, sp);
        } else if ((tagHdr & 32) == 0) {
            throw new IOException("indefinite-length primitive encoding encountered");
        } else {
            ASN1StreamParser sp2 = new ASN1StreamParser(new IndefiniteLengthInputStream(this._in, this._limit), this._limit, this.tmpBuffers);
            int tagClass2 = tagHdr & BERTags.PRIVATE;
            if (tagClass2 == 0) {
                return sp2.parseImplicitConstructedIL(tagNo);
            }
            if (64 == tagClass2) {
                return new BERApplicationSpecificParser(tagNo, sp2);
            }
            return new BERTaggedObjectParser(tagClass2, tagNo, sp2);
        }
    }

    /* access modifiers changed from: package-private */
    public ASN1Primitive loadTaggedDL(int tagClass, int tagNo, boolean constructed) throws IOException {
        if (!constructed) {
            return ASN1TaggedObject.createPrimitive(tagClass, tagNo, ((DefiniteLengthInputStream) this._in).toByteArray());
        }
        return ASN1TaggedObject.createConstructedDL(tagClass, tagNo, readVector());
    }

    /* access modifiers changed from: package-private */
    public ASN1Primitive loadTaggedIL(int tagClass, int tagNo) throws IOException {
        return ASN1TaggedObject.createConstructedIL(tagClass, tagNo, readVector());
    }

    /* access modifiers changed from: package-private */
    public ASN1Encodable parseImplicitConstructedDL(int univTagNo) throws IOException {
        switch (univTagNo) {
            case 3:
                return new BERBitStringParser(this);
            case 4:
                return new BEROctetStringParser(this);
            case 8:
                return new DERExternalParser(this);
            case 16:
                return new DLSequenceParser(this);
            case 17:
                return new DLSetParser(this);
            default:
                throw new ASN1Exception("unknown DL object encountered: 0x" + Integer.toHexString(univTagNo));
        }
    }

    /* access modifiers changed from: package-private */
    public ASN1Encodable parseImplicitConstructedIL(int univTagNo) throws IOException {
        switch (univTagNo) {
            case 3:
                return new BERBitStringParser(this);
            case 4:
                return new BEROctetStringParser(this);
            case 8:
                return new DERExternalParser(this);
            case 16:
                return new BERSequenceParser(this);
            case 17:
                return new BERSetParser(this);
            default:
                throw new ASN1Exception("unknown BER object encountered: 0x" + Integer.toHexString(univTagNo));
        }
    }

    /* access modifiers changed from: package-private */
    public ASN1Encodable parseImplicitPrimitive(int univTagNo) throws IOException {
        return parseImplicitPrimitive(univTagNo, (DefiniteLengthInputStream) this._in);
    }

    /* access modifiers changed from: package-private */
    public ASN1Encodable parseImplicitPrimitive(int univTagNo, DefiniteLengthInputStream defIn) throws IOException {
        switch (univTagNo) {
            case 3:
                return new DLBitStringParser(defIn);
            case 4:
                return new DEROctetStringParser(defIn);
            case 8:
                throw new ASN1Exception("externals must use constructed encoding (see X.690 8.18)");
            case 16:
                throw new ASN1Exception("sets must use constructed encoding (see X.690 8.11.1/8.12.1)");
            case 17:
                throw new ASN1Exception("sequences must use constructed encoding (see X.690 8.9.1/8.10.1)");
            default:
                try {
                    return ASN1InputStream.createPrimitiveDERObject(univTagNo, defIn, this.tmpBuffers);
                } catch (IllegalArgumentException e) {
                    throw new ASN1Exception("corrupted stream detected", e);
                }
        }
    }

    /* access modifiers changed from: package-private */
    public ASN1Encodable parseObject(int univTagNo) throws IOException {
        if (univTagNo < 0 || univTagNo > 30) {
            throw new IllegalArgumentException("invalid universal tag number: " + univTagNo);
        }
        int tagHdr = this._in.read();
        if (tagHdr < 0) {
            return null;
        }
        if ((tagHdr & -33) == univTagNo) {
            return implParseObject(tagHdr);
        }
        throw new IOException("unexpected identifier encountered: " + tagHdr);
    }

    /* access modifiers changed from: package-private */
    public ASN1TaggedObjectParser parseTaggedObject() throws IOException {
        int tagHdr = this._in.read();
        if (tagHdr < 0) {
            return null;
        }
        if ((tagHdr & BERTags.PRIVATE) != 0) {
            return (ASN1TaggedObjectParser) implParseObject(tagHdr);
        }
        throw new ASN1Exception("no tagged object found");
    }

    /* access modifiers changed from: package-private */
    public ASN1EncodableVector readVector() throws IOException {
        int tagHdr = this._in.read();
        if (tagHdr < 0) {
            return new ASN1EncodableVector(0);
        }
        ASN1EncodableVector v = new ASN1EncodableVector();
        do {
            ASN1Encodable obj = implParseObject(tagHdr);
            if (obj instanceof InMemoryRepresentable) {
                v.add(((InMemoryRepresentable) obj).getLoadedObject());
            } else {
                v.add(obj.toASN1Primitive());
            }
            tagHdr = this._in.read();
        } while (tagHdr >= 0);
        return v;
    }

    private void set00Check(boolean enabled) {
        if (this._in instanceof IndefiniteLengthInputStream) {
            ((IndefiniteLengthInputStream) this._in).setEofOn00(enabled);
        }
    }
}
