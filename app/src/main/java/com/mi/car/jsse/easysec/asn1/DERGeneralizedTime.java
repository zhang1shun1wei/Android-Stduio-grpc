package com.mi.car.jsse.easysec.asn1;

import com.mi.car.jsse.easysec.util.Strings;
import java.io.IOException;
import java.util.Date;

public class DERGeneralizedTime extends ASN1GeneralizedTime {
    public DERGeneralizedTime(byte[] time) {
        super(time);
    }

    public DERGeneralizedTime(Date time) {
        super(time);
    }

    public DERGeneralizedTime(String time) {
        super(time);
    }

    private byte[] getDERTime() {
        if (this.contents[this.contents.length - 1] != 90) {
            return this.contents;
        }
        if (!hasMinutes()) {
            byte[] derTime = new byte[(this.contents.length + 4)];
            System.arraycopy(this.contents, 0, derTime, 0, this.contents.length - 1);
            System.arraycopy(Strings.toByteArray("0000Z"), 0, derTime, this.contents.length - 1, 5);
            return derTime;
        } else if (!hasSeconds()) {
            byte[] derTime2 = new byte[(this.contents.length + 2)];
            System.arraycopy(this.contents, 0, derTime2, 0, this.contents.length - 1);
            System.arraycopy(Strings.toByteArray("00Z"), 0, derTime2, this.contents.length - 1, 3);
            return derTime2;
        } else if (!hasFractionalSeconds()) {
            return this.contents;
        } else {
            int ind = this.contents.length - 2;
            while (ind > 0 && this.contents[ind] == 48) {
                ind--;
            }
            if (this.contents[ind] == 46) {
                byte[] derTime3 = new byte[(ind + 1)];
                System.arraycopy(this.contents, 0, derTime3, 0, ind);
                derTime3[ind] = 90;
                return derTime3;
            }
            byte[] derTime4 = new byte[(ind + 2)];
            System.arraycopy(this.contents, 0, derTime4, 0, ind + 1);
            derTime4[ind + 1] = 90;
            return derTime4;
        }
    }

    /* access modifiers changed from: package-private */
    @Override // com.mi.car.jsse.easysec.asn1.ASN1GeneralizedTime, com.mi.car.jsse.easysec.asn1.ASN1Primitive
    public int encodedLength(boolean withTag) {
        return ASN1OutputStream.getLengthOfEncodingDL(withTag, getDERTime().length);
    }

    /* access modifiers changed from: package-private */
    @Override // com.mi.car.jsse.easysec.asn1.ASN1GeneralizedTime, com.mi.car.jsse.easysec.asn1.ASN1Primitive
    public void encode(ASN1OutputStream out, boolean withTag) throws IOException {
        out.writeEncodingDL(withTag, 24, getDERTime());
    }

    /* access modifiers changed from: package-private */
    @Override // com.mi.car.jsse.easysec.asn1.ASN1GeneralizedTime, com.mi.car.jsse.easysec.asn1.ASN1Primitive
    public ASN1Primitive toDERObject() {
        return this;
    }

    /* access modifiers changed from: package-private */
    @Override // com.mi.car.jsse.easysec.asn1.ASN1GeneralizedTime, com.mi.car.jsse.easysec.asn1.ASN1Primitive
    public ASN1Primitive toDLObject() {
        return this;
    }
}
