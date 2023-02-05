package com.mi.car.jsse.easysec.asn1;

/* access modifiers changed from: package-private */
public final class ASN1Tag {
    private final int tagClass;
    private final int tagNumber;

    static ASN1Tag create(int tagClass2, int tagNumber2) {
        return new ASN1Tag(tagClass2, tagNumber2);
    }

    private ASN1Tag(int tagClass2, int tagNumber2) {
        this.tagClass = tagClass2;
        this.tagNumber = tagNumber2;
    }

    /* access modifiers changed from: package-private */
    public int getTagClass() {
        return this.tagClass;
    }

    /* access modifiers changed from: package-private */
    public int getTagNumber() {
        return this.tagNumber;
    }
}
