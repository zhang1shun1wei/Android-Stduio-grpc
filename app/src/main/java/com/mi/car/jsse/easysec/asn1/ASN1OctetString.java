package com.mi.car.jsse.easysec.asn1;

import com.mi.car.jsse.easysec.util.Arrays;
import com.mi.car.jsse.easysec.util.Strings;
import com.mi.car.jsse.easysec.util.encoders.Hex;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;

public abstract class ASN1OctetString extends ASN1Primitive implements ASN1OctetStringParser {
    static final byte[] EMPTY_OCTETS = new byte[0];
    static final ASN1UniversalType TYPE = new ASN1UniversalType(ASN1OctetString.class, 4) {
        /* class com.mi.car.jsse.easysec.asn1.ASN1OctetString.AnonymousClass1 */

        /* access modifiers changed from: package-private */
        @Override // com.mi.car.jsse.easysec.asn1.ASN1UniversalType
        public ASN1Primitive fromImplicitPrimitive(DEROctetString octetString) {
            return octetString;
        }

        /* access modifiers changed from: package-private */
        @Override // com.mi.car.jsse.easysec.asn1.ASN1UniversalType
        public ASN1Primitive fromImplicitConstructed(ASN1Sequence sequence) {
            return sequence.toASN1OctetString();
        }
    };
    byte[] string;

    public static ASN1OctetString getInstance(ASN1TaggedObject taggedObject, boolean explicit) {
        return (ASN1OctetString) TYPE.getContextInstance(taggedObject, explicit);
    }

    public static ASN1OctetString getInstance(Object obj) {
        if (obj == null || (obj instanceof ASN1OctetString)) {
            return (ASN1OctetString) obj;
        }
        if (obj instanceof ASN1Encodable) {
            ASN1Primitive primitive = ((ASN1Encodable) obj).toASN1Primitive();
            if (primitive instanceof ASN1OctetString) {
                return (ASN1OctetString) primitive;
            }
        } else if (obj instanceof byte[]) {
            try {
                return (ASN1OctetString) TYPE.fromByteArray((byte[]) obj);
            } catch (IOException e) {
                throw new IllegalArgumentException("failed to construct OCTET STRING from byte[]: " + e.getMessage());
            }
        }
        throw new IllegalArgumentException("illegal object in getInstance: " + obj.getClass().getName());
    }

    public ASN1OctetString(byte[] string2) {
        if (string2 == null) {
            throw new NullPointerException("'string' cannot be null");
        }
        this.string = string2;
    }

    @Override // com.mi.car.jsse.easysec.asn1.ASN1OctetStringParser
    public InputStream getOctetStream() {
        return new ByteArrayInputStream(this.string);
    }

    public ASN1OctetStringParser parser() {
        return this;
    }

    public byte[] getOctets() {
        return this.string;
    }

    @Override // com.mi.car.jsse.easysec.asn1.ASN1Object, com.mi.car.jsse.easysec.asn1.ASN1Primitive
    public int hashCode() {
        return Arrays.hashCode(getOctets());
    }

    /* access modifiers changed from: package-private */
    @Override // com.mi.car.jsse.easysec.asn1.ASN1Primitive
    public boolean asn1Equals(ASN1Primitive o) {
        if (!(o instanceof ASN1OctetString)) {
            return false;
        }
        return Arrays.areEqual(this.string, ((ASN1OctetString) o).string);
    }

    @Override // com.mi.car.jsse.easysec.asn1.InMemoryRepresentable
    public ASN1Primitive getLoadedObject() {
        return toASN1Primitive();
    }

    /* access modifiers changed from: package-private */
    @Override // com.mi.car.jsse.easysec.asn1.ASN1Primitive
    public ASN1Primitive toDERObject() {
        return new DEROctetString(this.string);
    }

    /* access modifiers changed from: package-private */
    @Override // com.mi.car.jsse.easysec.asn1.ASN1Primitive
    public ASN1Primitive toDLObject() {
        return new DEROctetString(this.string);
    }

    public String toString() {
        return "#" + Strings.fromByteArray(Hex.encode(this.string));
    }

    static ASN1OctetString createPrimitive(byte[] contents) {
        return new DEROctetString(contents);
    }
}
