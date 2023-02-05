package com.mi.car.jsse.easysec.asn1;

import java.io.IOException;

public abstract class ASN1Util {
    static ASN1TaggedObject checkTag(ASN1TaggedObject taggedObject, int tagClass, int tagNo) {
        if (taggedObject.hasTag(tagClass, tagNo)) {
            return taggedObject;
        }
        String expected = getTagText(tagClass, tagNo);
        throw new IllegalStateException("Expected " + expected + " tag but found " + getTagText(taggedObject));
    }

    static ASN1TaggedObjectParser checkTag(ASN1TaggedObjectParser taggedObjectParser, int tagClass, int tagNo) {
        if (taggedObjectParser.hasTag(tagClass, tagNo)) {
            return taggedObjectParser;
        }
        String expected = getTagText(tagClass, tagNo);
        throw new IllegalStateException("Expected " + expected + " tag but found " + getTagText(taggedObjectParser));
    }

    static String getTagText(ASN1Tag tag) {
        return getTagText(tag.getTagClass(), tag.getTagNumber());
    }

    public static String getTagText(ASN1TaggedObject taggedObject) {
        return getTagText(taggedObject.getTagClass(), taggedObject.getTagNo());
    }

    public static String getTagText(ASN1TaggedObjectParser taggedObjectParser) {
        return getTagText(taggedObjectParser.getTagClass(), taggedObjectParser.getTagNo());
    }

    public static String getTagText(int tagClass, int tagNo) {
        switch (tagClass) {
            case 64:
                return "[APPLICATION " + tagNo + "]";
            case 128:
                return "[CONTEXT " + tagNo + "]";
            case BERTags.PRIVATE /*{ENCODED_INT: 192}*/:
                return "[PRIVATE " + tagNo + "]";
            default:
                return "[UNIVERSAL " + tagNo + "]";
        }
    }

    public static ASN1Object getExplicitBaseObject(ASN1TaggedObject taggedObject, int tagClass, int tagNo) {
        return checkTag(taggedObject, tagClass, tagNo).getExplicitBaseObject();
    }

    public static ASN1Object getExplicitContextBaseObject(ASN1TaggedObject taggedObject, int tagNo) {
        return getExplicitBaseObject(taggedObject, 128, tagNo);
    }

    public static ASN1Object tryGetExplicitBaseObject(ASN1TaggedObject taggedObject, int tagClass, int tagNo) {
        if (!taggedObject.hasTag(tagClass, tagNo)) {
            return null;
        }
        return taggedObject.getExplicitBaseObject();
    }

    public static ASN1Object tryGetExplicitContextBaseObject(ASN1TaggedObject taggedObject, int tagNo) {
        return tryGetExplicitBaseObject(taggedObject, 128, tagNo);
    }

    public static ASN1TaggedObject getExplicitBaseTagged(ASN1TaggedObject taggedObject, int tagClass, int tagNo) {
        return checkTag(taggedObject, tagClass, tagNo).getExplicitBaseTagged();
    }

    public static ASN1TaggedObject getExplicitContextBaseTagged(ASN1TaggedObject taggedObject, int tagNo) {
        return getExplicitBaseTagged(taggedObject, 128, tagNo);
    }

    public static ASN1TaggedObject tryGetExplicitBaseTagged(ASN1TaggedObject taggedObject, int tagClass, int tagNo) {
        if (!taggedObject.hasTag(tagClass, tagNo)) {
            return null;
        }
        return taggedObject.getExplicitBaseTagged();
    }

    public static ASN1TaggedObject tryGetExplicitContextBaseTagged(ASN1TaggedObject taggedObject, int tagNo) {
        return tryGetExplicitBaseTagged(taggedObject, 128, tagNo);
    }

    public static ASN1TaggedObject getImplicitBaseTagged(ASN1TaggedObject taggedObject, int tagClass, int tagNo, int baseTagClass, int baseTagNo) {
        return checkTag(taggedObject, tagClass, tagNo).getImplicitBaseTagged(baseTagClass, baseTagNo);
    }

    public static ASN1TaggedObject getImplicitContextBaseTagged(ASN1TaggedObject taggedObject, int tagNo, int baseTagClass, int baseTagNo) {
        return getImplicitBaseTagged(taggedObject, 128, tagNo, baseTagClass, baseTagNo);
    }

    public static ASN1TaggedObject tryGetImplicitBaseTagged(ASN1TaggedObject taggedObject, int tagClass, int tagNo, int baseTagClass, int baseTagNo) {
        if (!taggedObject.hasTag(tagClass, tagNo)) {
            return null;
        }
        return taggedObject.getImplicitBaseTagged(baseTagClass, baseTagNo);
    }

    public static ASN1TaggedObject tryGetImplicitContextBaseTagged(ASN1TaggedObject taggedObject, int tagNo, int baseTagClass, int baseTagNo) {
        return tryGetImplicitBaseTagged(taggedObject, 128, tagNo, baseTagClass, baseTagNo);
    }

    public static ASN1Primitive getBaseUniversal(ASN1TaggedObject taggedObject, int tagClass, int tagNo, boolean declaredExplicit, int baseTagNo) {
        return checkTag(taggedObject, tagClass, tagNo).getBaseUniversal(declaredExplicit, baseTagNo);
    }

    public static ASN1Primitive getContextBaseUniversal(ASN1TaggedObject taggedObject, int tagNo, boolean declaredExplicit, int baseTagNo) {
        return getBaseUniversal(taggedObject, 128, tagNo, declaredExplicit, baseTagNo);
    }

    public static ASN1Primitive tryGetBaseUniversal(ASN1TaggedObject taggedObject, int tagClass, int tagNo, boolean declaredExplicit, int baseTagNo) {
        if (!taggedObject.hasTag(tagClass, tagNo)) {
            return null;
        }
        return taggedObject.getBaseUniversal(declaredExplicit, baseTagNo);
    }

    public static ASN1Primitive tryGetContextBaseUniversal(ASN1TaggedObject taggedObject, int tagNo, boolean declaredExplicit, int baseTagNo) {
        return tryGetBaseUniversal(taggedObject, 128, tagNo, declaredExplicit, baseTagNo);
    }

    public static ASN1TaggedObjectParser parseExplicitBaseTagged(ASN1TaggedObjectParser taggedObjectParser, int tagClass, int tagNo) throws IOException {
        return checkTag(taggedObjectParser, tagClass, tagNo).parseExplicitBaseTagged();
    }

    public static ASN1TaggedObjectParser parseExplicitContextBaseTagged(ASN1TaggedObjectParser taggedObjectParser, int tagNo) throws IOException {
        return parseExplicitBaseTagged(taggedObjectParser, 128, tagNo);
    }

    public static ASN1TaggedObjectParser tryParseExplicitBaseTagged(ASN1TaggedObjectParser taggedObjectParser, int tagClass, int tagNo) throws IOException {
        if (!taggedObjectParser.hasTag(tagClass, tagNo)) {
            return null;
        }
        return taggedObjectParser.parseExplicitBaseTagged();
    }

    public static ASN1TaggedObjectParser tryParseExplicitContextBaseTagged(ASN1TaggedObjectParser taggedObjectParser, int tagNo) throws IOException {
        return tryParseExplicitBaseTagged(taggedObjectParser, 128, tagNo);
    }

    public static ASN1TaggedObjectParser parseImplicitBaseTagged(ASN1TaggedObjectParser taggedObjectParser, int tagClass, int tagNo, int baseTagClass, int baseTagNo) throws IOException {
        return checkTag(taggedObjectParser, tagClass, tagNo).parseImplicitBaseTagged(baseTagClass, baseTagNo);
    }

    public static ASN1TaggedObjectParser parseImplicitContextBaseTagged(ASN1TaggedObjectParser taggedObjectParser, int tagNo, int baseTagClass, int baseTagNo) throws IOException {
        return parseImplicitBaseTagged(taggedObjectParser, 128, tagNo, baseTagClass, baseTagNo);
    }

    public static ASN1TaggedObjectParser tryParseImplicitBaseTagged(ASN1TaggedObjectParser taggedObjectParser, int tagClass, int tagNo, int baseTagClass, int baseTagNo) throws IOException {
        if (!taggedObjectParser.hasTag(tagClass, tagNo)) {
            return null;
        }
        return taggedObjectParser.parseImplicitBaseTagged(baseTagClass, baseTagNo);
    }

    public static ASN1TaggedObjectParser tryParseImplicitContextBaseTagged(ASN1TaggedObjectParser taggedObjectParser, int tagNo, int baseTagClass, int baseTagNo) throws IOException {
        return tryParseImplicitBaseTagged(taggedObjectParser, 128, tagNo, baseTagClass, baseTagNo);
    }

    public static ASN1Encodable parseBaseUniversal(ASN1TaggedObjectParser taggedObjectParser, int tagClass, int tagNo, boolean declaredExplicit, int baseTagNo) throws IOException {
        return checkTag(taggedObjectParser, tagClass, tagNo).parseBaseUniversal(declaredExplicit, baseTagNo);
    }

    public static ASN1Encodable parseContextBaseUniversal(ASN1TaggedObjectParser taggedObjectParser, int tagNo, boolean declaredExplicit, int baseTagNo) throws IOException {
        return parseBaseUniversal(taggedObjectParser, 128, tagNo, declaredExplicit, baseTagNo);
    }

    public static ASN1Encodable tryParseBaseUniversal(ASN1TaggedObjectParser taggedObjectParser, int tagClass, int tagNo, boolean declaredExplicit, int baseTagNo) throws IOException {
        if (!taggedObjectParser.hasTag(tagClass, tagNo)) {
            return null;
        }
        return taggedObjectParser.parseBaseUniversal(declaredExplicit, baseTagNo);
    }

    public static ASN1Encodable tryParseContextBaseUniversal(ASN1TaggedObjectParser taggedObjectParser, int tagNo, boolean declaredExplicit, int baseTagNo) throws IOException {
        return tryParseBaseUniversal(taggedObjectParser, 128, tagNo, declaredExplicit, baseTagNo);
    }

    public static ASN1Encodable parseExplicitBaseObject(ASN1TaggedObjectParser taggedObjectParser, int tagClass, int tagNo) throws IOException {
        return checkTag(taggedObjectParser, tagClass, tagNo).parseExplicitBaseObject();
    }

    public static ASN1Encodable parseExplicitContextBaseObject(ASN1TaggedObjectParser taggedObjectParser, int tagNo) throws IOException {
        return parseExplicitBaseObject(taggedObjectParser, 128, tagNo);
    }

    public static ASN1Encodable tryParseExplicitBaseObject(ASN1TaggedObjectParser taggedObjectParser, int tagClass, int tagNo) throws IOException {
        if (!taggedObjectParser.hasTag(tagClass, tagNo)) {
            return null;
        }
        return taggedObjectParser.parseExplicitBaseObject();
    }

    public static ASN1Encodable tryParseExplicitContextBaseObject(ASN1TaggedObjectParser taggedObjectParser, int tagNo) throws IOException {
        return tryParseExplicitBaseObject(taggedObjectParser, 128, tagNo);
    }
}
