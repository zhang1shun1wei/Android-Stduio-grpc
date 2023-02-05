package com.mi.car.jsse.easysec.asn1;

import com.mi.car.jsse.easysec.util.Arrays;
import com.mi.car.jsse.easysec.util.Strings;
import java.io.IOException;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.Locale;
import java.util.SimpleTimeZone;
import java.util.TimeZone;

public class ASN1GeneralizedTime extends ASN1Primitive {
    static final ASN1UniversalType TYPE = new ASN1UniversalType(ASN1GeneralizedTime.class, 24) {
        public ASN1Primitive fromImplicitPrimitive(DEROctetString octetString) {
            return ASN1GeneralizedTime.createPrimitive(octetString.getOctets());
        }
    };
    final byte[] contents;

    public static ASN1GeneralizedTime getInstance(Object obj) {
        if (obj != null && !(obj instanceof ASN1GeneralizedTime)) {
            if (obj instanceof ASN1Encodable) {
                ASN1Primitive primitive = ((ASN1Encodable)obj).toASN1Primitive();
                if (primitive instanceof ASN1GeneralizedTime) {
                    return (ASN1GeneralizedTime)primitive;
                }
            }

            if (obj instanceof byte[]) {
                try {
                    return (ASN1GeneralizedTime)TYPE.fromByteArray((byte[])((byte[])obj));
                } catch (Exception var2) {
                    throw new IllegalArgumentException("encoding error in getInstance: " + var2.toString());
                }
            } else {
                throw new IllegalArgumentException("illegal object in getInstance: " + obj.getClass().getName());
            }
        } else {
            return (ASN1GeneralizedTime)obj;
        }
    }

    public static ASN1GeneralizedTime getInstance(ASN1TaggedObject taggedObject, boolean explicit) {
        return (ASN1GeneralizedTime)TYPE.getContextInstance(taggedObject, explicit);
    }

    public ASN1GeneralizedTime(String time) {
        this.contents = Strings.toByteArray(time);

        try {
            this.getDate();
        } catch (ParseException var3) {
            throw new IllegalArgumentException("invalid date string: " + var3.getMessage());
        }
    }

    public ASN1GeneralizedTime(Date time) {
        SimpleDateFormat dateF = new SimpleDateFormat("yyyyMMddHHmmss'Z'", DateUtil.EN_Locale);
        dateF.setTimeZone(new SimpleTimeZone(0, "Z"));
        this.contents = Strings.toByteArray(dateF.format(time));
    }

    public ASN1GeneralizedTime(Date time, Locale locale) {
        SimpleDateFormat dateF = new SimpleDateFormat("yyyyMMddHHmmss'Z'", locale);
        dateF.setTimeZone(new SimpleTimeZone(0, "Z"));
        this.contents = Strings.toByteArray(dateF.format(time));
    }

    ASN1GeneralizedTime(byte[] bytes) {
        if (bytes.length < 4) {
            throw new IllegalArgumentException("GeneralizedTime string too short");
        } else {
            this.contents = bytes;
            if (!this.isDigit(0) || !this.isDigit(1) || !this.isDigit(2) || !this.isDigit(3)) {
                throw new IllegalArgumentException("illegal characters in GeneralizedTime string");
            }
        }
    }

    public String getTimeString() {
        return Strings.fromByteArray(this.contents);
    }

    public String getTime() {
        String stime = Strings.fromByteArray(this.contents);
        if (stime.charAt(stime.length() - 1) == 'Z') {
            return stime.substring(0, stime.length() - 1) + "GMT+00:00";
        } else {
            int signPos = stime.length() - 6;
            char sign = stime.charAt(signPos);
            if ((sign == '-' || sign == '+') && stime.indexOf("GMT") == signPos - 3) {
                return stime;
            } else {
                signPos = stime.length() - 5;
                sign = stime.charAt(signPos);
                if (sign != '-' && sign != '+') {
                    signPos = stime.length() - 3;
                    sign = stime.charAt(signPos);
                    return sign != '-' && sign != '+' ? stime + this.calculateGMTOffset(stime) : stime.substring(0, signPos) + "GMT" + stime.substring(signPos) + ":00";
                } else {
                    return stime.substring(0, signPos) + "GMT" + stime.substring(signPos, signPos + 3) + ":" + stime.substring(signPos + 3);
                }
            }
        }
    }

    private String calculateGMTOffset(String stime) {
        String sign = "+";
        TimeZone timeZone = TimeZone.getDefault();
        int offset = timeZone.getRawOffset();
        if (offset < 0) {
            sign = "-";
            offset = -offset;
        }

        int hours = offset / 3600000;
        int minutes = (offset - hours * 60 * 60 * 1000) / '\uea60';

        try {
            if (timeZone.useDaylightTime()) {
                if (this.hasFractionalSeconds()) {
                    stime = this.pruneFractionalSeconds(stime);
                }

                SimpleDateFormat dateF = this.calculateGMTDateFormat();
                if (timeZone.inDaylightTime(dateF.parse(stime + "GMT" + sign + this.convert(hours) + ":" + this.convert(minutes)))) {
                    hours += sign.equals("+") ? 1 : -1;
                }
            }
        } catch (ParseException var8) {
        }

        return "GMT" + sign + this.convert(hours) + ":" + this.convert(minutes);
    }

    private SimpleDateFormat calculateGMTDateFormat() {
        SimpleDateFormat dateF;
        if (this.hasFractionalSeconds()) {
            dateF = new SimpleDateFormat("yyyyMMddHHmmss.SSSz");
        } else if (this.hasSeconds()) {
            dateF = new SimpleDateFormat("yyyyMMddHHmmssz");
        } else if (this.hasMinutes()) {
            dateF = new SimpleDateFormat("yyyyMMddHHmmz");
        } else {
            dateF = new SimpleDateFormat("yyyyMMddHHz");
        }

        dateF.setTimeZone(new SimpleTimeZone(0, "Z"));
        return dateF;
    }

    private String pruneFractionalSeconds(String origTime) {
        String frac = origTime.substring(14);

        int index;
        for(index = 1; index < frac.length(); ++index) {
            char ch = frac.charAt(index);
            if ('0' > ch || ch > '9') {
                break;
            }
        }

        if (index - 1 > 3) {
            frac = frac.substring(0, 4) + frac.substring(index);
            origTime = origTime.substring(0, 14) + frac;
        } else if (index - 1 == 1) {
            frac = frac.substring(0, index) + "00" + frac.substring(index);
            origTime = origTime.substring(0, 14) + frac;
        } else if (index - 1 == 2) {
            frac = frac.substring(0, index) + "0" + frac.substring(index);
            origTime = origTime.substring(0, 14) + frac;
        }

        return origTime;
    }

    private String convert(int time) {
        return time < 10 ? "0" + time : Integer.toString(time);
    }

    public Date getDate() throws ParseException {
        String stime = Strings.fromByteArray(this.contents);
        String d = stime;
        SimpleDateFormat dateF;
        if (stime.endsWith("Z")) {
            if (this.hasFractionalSeconds()) {
                dateF = new SimpleDateFormat("yyyyMMddHHmmss.SSS'Z'");
            } else if (this.hasSeconds()) {
                dateF = new SimpleDateFormat("yyyyMMddHHmmss'Z'");
            } else if (this.hasMinutes()) {
                dateF = new SimpleDateFormat("yyyyMMddHHmm'Z'");
            } else {
                dateF = new SimpleDateFormat("yyyyMMddHH'Z'");
            }

            dateF.setTimeZone(new SimpleTimeZone(0, "Z"));
        } else if (stime.indexOf(45) <= 0 && stime.indexOf(43) <= 0) {
            if (this.hasFractionalSeconds()) {
                dateF = new SimpleDateFormat("yyyyMMddHHmmss.SSS");
            } else if (this.hasSeconds()) {
                dateF = new SimpleDateFormat("yyyyMMddHHmmss");
            } else if (this.hasMinutes()) {
                dateF = new SimpleDateFormat("yyyyMMddHHmm");
            } else {
                dateF = new SimpleDateFormat("yyyyMMddHH");
            }

            dateF.setTimeZone(new SimpleTimeZone(0, TimeZone.getDefault().getID()));
        } else {
            d = this.getTime();
            dateF = this.calculateGMTDateFormat();
        }

        if (this.hasFractionalSeconds()) {
            d = this.pruneFractionalSeconds(d);
        }

        return DateUtil.epochAdjust(dateF.parse(d));
    }

    protected boolean hasFractionalSeconds() {
        for(int i = 0; i != this.contents.length; ++i) {
            if (this.contents[i] == 46 && i == 14) {
                return true;
            }
        }

        return false;
    }

    protected boolean hasSeconds() {
        return this.isDigit(12) && this.isDigit(13);
    }

    protected boolean hasMinutes() {
        return this.isDigit(10) && this.isDigit(11);
    }

    private boolean isDigit(int pos) {
        return this.contents.length > pos && this.contents[pos] >= 48 && this.contents[pos] <= 57;
    }

    public final boolean encodeConstructed() {
        return false;
    }

    public int encodedLength(boolean withTag) {
        return ASN1OutputStream.getLengthOfEncodingDL(withTag, this.contents.length);
    }

    public void encode(ASN1OutputStream out, boolean withTag) throws IOException {
        out.writeEncodingDL(withTag, 24, this.contents);
    }

    public ASN1Primitive toDERObject() {
        return new DERGeneralizedTime(this.contents);
    }

    public ASN1Primitive toDLObject() {
        return new DERGeneralizedTime(this.contents);
    }

    public boolean asn1Equals(ASN1Primitive o) {
        return !(o instanceof ASN1GeneralizedTime) ? false : Arrays.areEqual(this.contents, ((ASN1GeneralizedTime)o).contents);
    }

    public int hashCode() {
        return Arrays.hashCode(this.contents);
    }

    static ASN1GeneralizedTime createPrimitive(byte[] contents) {
        return new ASN1GeneralizedTime(contents);
    }
}