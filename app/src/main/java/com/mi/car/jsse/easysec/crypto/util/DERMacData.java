package com.mi.car.jsse.easysec.crypto.util;

import com.mi.car.jsse.easysec.asn1.ASN1Encodable;
import com.mi.car.jsse.easysec.asn1.ASN1OctetString;
import com.mi.car.jsse.easysec.asn1.DERTaggedObject;
import com.mi.car.jsse.easysec.util.Arrays;
import com.mi.car.jsse.easysec.util.Strings;

public final class DERMacData {
    private final byte[] macData;

    public enum Type {
        UNILATERALU("KC_1_U"),
        UNILATERALV("KC_1_V"),
        BILATERALU("KC_2_U"),
        BILATERALV("KC_2_V");
        
        private final String enc;

        private Type(String enc2) {
            this.enc = enc2;
        }

        public byte[] getHeader() {
            return Strings.toByteArray(this.enc);
        }
    }

    public static final class Builder {
        private ASN1OctetString ephemDataU;
        private ASN1OctetString ephemDataV;
        private ASN1OctetString idU;
        private ASN1OctetString idV;
        private byte[] text;
        private final Type type;

        public Builder(Type type2, byte[] idU2, byte[] idV2, byte[] ephemDataU2, byte[] ephemDataV2) {
            this.type = type2;
            this.idU = DerUtil.getOctetString(idU2);
            this.idV = DerUtil.getOctetString(idV2);
            this.ephemDataU = DerUtil.getOctetString(ephemDataU2);
            this.ephemDataV = DerUtil.getOctetString(ephemDataV2);
        }

        public Builder withText(byte[] text2) {
            this.text = DerUtil.toByteArray(new DERTaggedObject(false, 0, (ASN1Encodable) DerUtil.getOctetString(text2)));
            return this;
        }

        public DERMacData build() {
            switch (this.type) {
                case UNILATERALU:
                case BILATERALU:
                    return new DERMacData(concatenate(this.type.getHeader(), DerUtil.toByteArray(this.idU), DerUtil.toByteArray(this.idV), DerUtil.toByteArray(this.ephemDataU), DerUtil.toByteArray(this.ephemDataV), this.text));
                case UNILATERALV:
                case BILATERALV:
                    return new DERMacData(concatenate(this.type.getHeader(), DerUtil.toByteArray(this.idV), DerUtil.toByteArray(this.idU), DerUtil.toByteArray(this.ephemDataV), DerUtil.toByteArray(this.ephemDataU), this.text));
                default:
                    throw new IllegalStateException("Unknown type encountered in build");
            }
        }

        private byte[] concatenate(byte[] header, byte[] id1, byte[] id2, byte[] ed1, byte[] ed2, byte[] text2) {
            return Arrays.concatenate(Arrays.concatenate(header, id1, id2), Arrays.concatenate(ed1, ed2, text2));
        }
    }

    private DERMacData(byte[] macData2) {
        this.macData = macData2;
    }

    public byte[] getMacData() {
        return Arrays.clone(this.macData);
    }
}
