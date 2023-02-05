package com.mi.car.jsse.easysec.asn1;

import com.mi.car.jsse.easysec.util.Arrays;
import com.mi.car.jsse.easysec.util.Strings;
import java.io.IOException;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.Locale;
import java.util.SimpleTimeZone;

public class ASN1UTCTime extends ASN1Primitive {
    static final ASN1UniversalType TYPE = new ASN1UniversalType(ASN1UTCTime.class, 23) {
        /* class com.mi.car.jsse.easysec.asn1.ASN1UTCTime.AnonymousClass1 */

        /* access modifiers changed from: package-private */
        @Override // com.mi.car.jsse.easysec.asn1.ASN1UniversalType
        public ASN1Primitive fromImplicitPrimitive(DEROctetString octetString) {
            return ASN1UTCTime.createPrimitive(octetString.getOctets());
        }
    };
    final byte[] contents;

    public static ASN1UTCTime getInstance(Object obj) {
        if (obj == null || (obj instanceof ASN1UTCTime)) {
            return (ASN1UTCTime) obj;
        }
        if (obj instanceof ASN1Encodable) {
            ASN1Primitive primitive = ((ASN1Encodable) obj).toASN1Primitive();
            if (primitive instanceof ASN1UTCTime) {
                return (ASN1UTCTime) primitive;
            }
        }
        if (obj instanceof byte[]) {
            try {
                return (ASN1UTCTime) TYPE.fromByteArray((byte[]) obj);
            } catch (Exception e) {
                throw new IllegalArgumentException("encoding error in getInstance: " + e.toString());
            }
        } else {
            throw new IllegalArgumentException("illegal object in getInstance: " + obj.getClass().getName());
        }
    }

    public static ASN1UTCTime getInstance(ASN1TaggedObject taggedObject, boolean explicit) {
        return (ASN1UTCTime) TYPE.getContextInstance(taggedObject, explicit);
    }

    public ASN1UTCTime(String time) {
        this.contents = Strings.toByteArray(time);
        try {
            getDate();
        } catch (ParseException e) {
            throw new IllegalArgumentException("invalid date string: " + e.getMessage());
        }
    }

    public ASN1UTCTime(Date time) {
        SimpleDateFormat dateF = new SimpleDateFormat("yyMMddHHmmss'Z'", DateUtil.EN_Locale);
        dateF.setTimeZone(new SimpleTimeZone(0, "Z"));
        this.contents = Strings.toByteArray(dateF.format(time));
    }

    public ASN1UTCTime(Date time, Locale locale) {
        SimpleDateFormat dateF = new SimpleDateFormat("yyMMddHHmmss'Z'", locale);
        dateF.setTimeZone(new SimpleTimeZone(0, "Z"));
        this.contents = Strings.toByteArray(dateF.format(time));
    }

    ASN1UTCTime(byte[] contents2) {
        if (contents2.length < 2) {
            throw new IllegalArgumentException("UTCTime string too short");
        }
        this.contents = contents2;
        if (!isDigit(0) || !isDigit(1)) {
            throw new IllegalArgumentException("illegal characters in UTCTime string");
        }
    }

    public Date getDate() throws ParseException {
        return DateUtil.epochAdjust(new SimpleDateFormat("yyMMddHHmmssz").parse(getTime()));
    }

    public Date getAdjustedDate() throws ParseException {
        SimpleDateFormat dateF = new SimpleDateFormat("yyyyMMddHHmmssz");
        dateF.setTimeZone(new SimpleTimeZone(0, "Z"));
        return DateUtil.epochAdjust(dateF.parse(getAdjustedTime()));
    }

    public String getTime() {
        String stime = Strings.fromByteArray(this.contents);
        if (stime.indexOf(45) >= 0 || stime.indexOf(43) >= 0) {
            int index = stime.indexOf(45);
            if (index < 0) {
                index = stime.indexOf(43);
            }
            String d = stime;
            if (index == stime.length() - 3) {
                d = d + "00";
            }
            if (index == 10) {
                return d.substring(0, 10) + "00GMT" + d.substring(10, 13) + ":" + d.substring(13, 15);
            }
            return d.substring(0, 12) + "GMT" + d.substring(12, 15) + ":" + d.substring(15, 17);
        } else if (stime.length() == 11) {
            return stime.substring(0, 10) + "00GMT+00:00";
        } else {
            return stime.substring(0, 12) + "GMT+00:00";
        }
    }

    public String getAdjustedTime() {
        String d = getTime();
        if (d.charAt(0) < '5') {
            return "20" + d;
        }
        return "19" + d;
    }

    private boolean isDigit(int pos) {
        return this.contents.length > pos && this.contents[pos] >= 48 && this.contents[pos] <= 57;
    }

    /* access modifiers changed from: package-private */
    @Override // com.mi.car.jsse.easysec.asn1.ASN1Primitive
    public final boolean encodeConstructed() {
        return false;
    }

    /* access modifiers changed from: package-private */
    @Override // com.mi.car.jsse.easysec.asn1.ASN1Primitive
    public int encodedLength(boolean withTag) {
        return ASN1OutputStream.getLengthOfEncodingDL(withTag, this.contents.length);
    }

    /* access modifiers changed from: package-private */
    @Override // com.mi.car.jsse.easysec.asn1.ASN1Primitive
    public void encode(ASN1OutputStream out, boolean withTag) throws IOException {
        out.writeEncodingDL(withTag, 23, this.contents);
    }

    /* access modifiers changed from: package-private */
    @Override // com.mi.car.jsse.easysec.asn1.ASN1Primitive
    public boolean asn1Equals(ASN1Primitive o) {
        if (!(o instanceof ASN1UTCTime)) {
            return false;
        }
        return Arrays.areEqual(this.contents, ((ASN1UTCTime) o).contents);
    }

    @Override // com.mi.car.jsse.easysec.asn1.ASN1Object, com.mi.car.jsse.easysec.asn1.ASN1Primitive
    public int hashCode() {
        return Arrays.hashCode(this.contents);
    }

    public String toString() {
        return Strings.fromByteArray(this.contents);
    }

    static ASN1UTCTime createPrimitive(byte[] contents2) {
        return new ASN1UTCTime(contents2);
    }
}
