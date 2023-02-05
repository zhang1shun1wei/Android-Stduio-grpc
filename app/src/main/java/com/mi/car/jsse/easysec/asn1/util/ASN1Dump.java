package com.mi.car.jsse.easysec.asn1.util;

import com.mi.car.jsse.easysec.asn1.ASN1ApplicationSpecific;
import com.mi.car.jsse.easysec.asn1.ASN1BMPString;
import com.mi.car.jsse.easysec.asn1.ASN1BitString;
import com.mi.car.jsse.easysec.asn1.ASN1Boolean;
import com.mi.car.jsse.easysec.asn1.ASN1Encodable;
import com.mi.car.jsse.easysec.asn1.ASN1Enumerated;
import com.mi.car.jsse.easysec.asn1.ASN1External;
import com.mi.car.jsse.easysec.asn1.ASN1GeneralizedTime;
import com.mi.car.jsse.easysec.asn1.ASN1GraphicString;
import com.mi.car.jsse.easysec.asn1.ASN1IA5String;
import com.mi.car.jsse.easysec.asn1.ASN1Integer;
import com.mi.car.jsse.easysec.asn1.ASN1Null;
import com.mi.car.jsse.easysec.asn1.ASN1NumericString;
import com.mi.car.jsse.easysec.asn1.ASN1ObjectDescriptor;
import com.mi.car.jsse.easysec.asn1.ASN1ObjectIdentifier;
import com.mi.car.jsse.easysec.asn1.ASN1OctetString;
import com.mi.car.jsse.easysec.asn1.ASN1Primitive;
import com.mi.car.jsse.easysec.asn1.ASN1PrintableString;
import com.mi.car.jsse.easysec.asn1.ASN1RelativeOID;
import com.mi.car.jsse.easysec.asn1.ASN1Sequence;
import com.mi.car.jsse.easysec.asn1.ASN1Set;
import com.mi.car.jsse.easysec.asn1.ASN1T61String;
import com.mi.car.jsse.easysec.asn1.ASN1TaggedObject;
import com.mi.car.jsse.easysec.asn1.ASN1UTCTime;
import com.mi.car.jsse.easysec.asn1.ASN1UTF8String;
import com.mi.car.jsse.easysec.asn1.ASN1Util;
import com.mi.car.jsse.easysec.asn1.ASN1VideotexString;
import com.mi.car.jsse.easysec.asn1.ASN1VisibleString;
import com.mi.car.jsse.easysec.asn1.BEROctetString;
import com.mi.car.jsse.easysec.asn1.BERSequence;
import com.mi.car.jsse.easysec.asn1.BERSet;
import com.mi.car.jsse.easysec.asn1.BERTaggedObject;
import com.mi.car.jsse.easysec.asn1.DERBitString;
import com.mi.car.jsse.easysec.asn1.DERSequence;
import com.mi.car.jsse.easysec.asn1.DERSet;
import com.mi.car.jsse.easysec.asn1.DERTaggedObject;
import com.mi.car.jsse.easysec.asn1.DLBitString;
import com.mi.car.jsse.easysec.util.Strings;
import com.mi.car.jsse.easysec.util.encoders.Hex;

public class ASN1Dump {
    private static final int SAMPLE_SIZE = 32;
    private static final String TAB = "    ";

    static void _dumpAsString(String indent, boolean verbose, ASN1Primitive obj, StringBuffer buf) {
        String nl = Strings.lineSeparator();
        if (obj instanceof ASN1Null) {
            buf.append(indent);
            buf.append("NULL");
            buf.append(nl);
        } else if (obj instanceof ASN1Sequence) {
            buf.append(indent);
            if (obj instanceof BERSequence) {
                buf.append("BER Sequence");
            } else if (obj instanceof DERSequence) {
                buf.append("DER Sequence");
            } else {
                buf.append("Sequence");
            }
            buf.append(nl);
            ASN1Sequence sequence = (ASN1Sequence) obj;
            String elementsIndent = indent + TAB;
            int count = sequence.size();
            for (int i = 0; i < count; i++) {
                _dumpAsString(elementsIndent, verbose, sequence.getObjectAt(i).toASN1Primitive(), buf);
            }
        } else if (obj instanceof ASN1Set) {
            buf.append(indent);
            if (obj instanceof BERSet) {
                buf.append("BER Set");
            } else if (obj instanceof DERSet) {
                buf.append("DER Set");
            } else {
                buf.append("Set");
            }
            buf.append(nl);
            ASN1Set set = (ASN1Set) obj;
            String elementsIndent2 = indent + TAB;
            int count2 = set.size();
            for (int i2 = 0; i2 < count2; i2++) {
                _dumpAsString(elementsIndent2, verbose, set.getObjectAt(i2).toASN1Primitive(), buf);
            }
        } else if (obj instanceof ASN1ApplicationSpecific) {
            _dumpAsString(indent, verbose, ((ASN1ApplicationSpecific) obj).getTaggedObject(), buf);
        } else if (obj instanceof ASN1TaggedObject) {
            buf.append(indent);
            if (obj instanceof BERTaggedObject) {
                buf.append("BER Tagged ");
            } else if (obj instanceof DERTaggedObject) {
                buf.append("DER Tagged ");
            } else {
                buf.append("Tagged ");
            }
            ASN1TaggedObject o = (ASN1TaggedObject) obj;
            buf.append(ASN1Util.getTagText(o));
            if (!o.isExplicit()) {
                buf.append(" IMPLICIT ");
            }
            buf.append(nl);
            _dumpAsString(indent + TAB, verbose, o.getBaseObject().toASN1Primitive(), buf);
        } else if (obj instanceof ASN1OctetString) {
            ASN1OctetString oct = (ASN1OctetString) obj;
            if (obj instanceof BEROctetString) {
                buf.append(indent + "BER Constructed Octet String[" + oct.getOctets().length + "] ");
            } else {
                buf.append(indent + "DER Octet String[" + oct.getOctets().length + "] ");
            }
            if (verbose) {
                buf.append(dumpBinaryDataAsString(indent, oct.getOctets()));
            } else {
                buf.append(nl);
            }
        } else if (obj instanceof ASN1ObjectIdentifier) {
            buf.append(indent + "ObjectIdentifier(" + ((ASN1ObjectIdentifier) obj).getId() + ")" + nl);
        } else if (obj instanceof ASN1RelativeOID) {
            buf.append(indent + "RelativeOID(" + ((ASN1RelativeOID) obj).getId() + ")" + nl);
        } else if (obj instanceof ASN1Boolean) {
            buf.append(indent + "Boolean(" + ((ASN1Boolean) obj).isTrue() + ")" + nl);
        } else if (obj instanceof ASN1Integer) {
            buf.append(indent + "Integer(" + ((ASN1Integer) obj).getValue() + ")" + nl);
        } else if (obj instanceof ASN1BitString) {
            ASN1BitString bitString = (ASN1BitString) obj;
            byte[] bytes = bitString.getBytes();
            int padBits = bitString.getPadBits();
            if (bitString instanceof DERBitString) {
                buf.append(indent + "DER Bit String[" + bytes.length + ", " + padBits + "] ");
            } else if (bitString instanceof DLBitString) {
                buf.append(indent + "DL Bit String[" + bytes.length + ", " + padBits + "] ");
            } else {
                buf.append(indent + "BER Bit String[" + bytes.length + ", " + padBits + "] ");
            }
            if (verbose) {
                buf.append(dumpBinaryDataAsString(indent, bytes));
            } else {
                buf.append(nl);
            }
        } else if (obj instanceof ASN1IA5String) {
            buf.append(indent + "IA5String(" + ((ASN1IA5String) obj).getString() + ") " + nl);
        } else if (obj instanceof ASN1UTF8String) {
            buf.append(indent + "UTF8String(" + ((ASN1UTF8String) obj).getString() + ") " + nl);
        } else if (obj instanceof ASN1NumericString) {
            buf.append(indent + "NumericString(" + ((ASN1NumericString) obj).getString() + ") " + nl);
        } else if (obj instanceof ASN1PrintableString) {
            buf.append(indent + "PrintableString(" + ((ASN1PrintableString) obj).getString() + ") " + nl);
        } else if (obj instanceof ASN1VisibleString) {
            buf.append(indent + "VisibleString(" + ((ASN1VisibleString) obj).getString() + ") " + nl);
        } else if (obj instanceof ASN1BMPString) {
            buf.append(indent + "BMPString(" + ((ASN1BMPString) obj).getString() + ") " + nl);
        } else if (obj instanceof ASN1T61String) {
            buf.append(indent + "T61String(" + ((ASN1T61String) obj).getString() + ") " + nl);
        } else if (obj instanceof ASN1GraphicString) {
            buf.append(indent + "GraphicString(" + ((ASN1GraphicString) obj).getString() + ") " + nl);
        } else if (obj instanceof ASN1VideotexString) {
            buf.append(indent + "VideotexString(" + ((ASN1VideotexString) obj).getString() + ") " + nl);
        } else if (obj instanceof ASN1UTCTime) {
            buf.append(indent + "UTCTime(" + ((ASN1UTCTime) obj).getTime() + ") " + nl);
        } else if (obj instanceof ASN1GeneralizedTime) {
            buf.append(indent + "GeneralizedTime(" + ((ASN1GeneralizedTime) obj).getTime() + ") " + nl);
        } else if (obj instanceof ASN1Enumerated) {
            buf.append(indent + "DER Enumerated(" + ((ASN1Enumerated) obj).getValue() + ")" + nl);
        } else if (obj instanceof ASN1ObjectDescriptor) {
            buf.append(indent + "ObjectDescriptor(" + ((ASN1ObjectDescriptor) obj).getBaseGraphicString().getString() + ") " + nl);
        } else if (obj instanceof ASN1External) {
            ASN1External ext = (ASN1External) obj;
            buf.append(indent + "External " + nl);
            String tab = indent + TAB;
            if (ext.getDirectReference() != null) {
                buf.append(tab + "Direct Reference: " + ext.getDirectReference().getId() + nl);
            }
            if (ext.getIndirectReference() != null) {
                buf.append(tab + "Indirect Reference: " + ext.getIndirectReference().toString() + nl);
            }
            if (ext.getDataValueDescriptor() != null) {
                _dumpAsString(tab, verbose, ext.getDataValueDescriptor(), buf);
            }
            buf.append(tab + "Encoding: " + ext.getEncoding() + nl);
            _dumpAsString(tab, verbose, ext.getExternalContent(), buf);
        } else {
            buf.append(indent + obj.toString() + nl);
        }
    }

    public static String dumpAsString(Object obj) {
        return dumpAsString(obj, false);
    }

    public static String dumpAsString(Object obj, boolean verbose) {
        ASN1Primitive primitive;
        if (obj instanceof ASN1Primitive) {
            primitive = (ASN1Primitive) obj;
        } else if (!(obj instanceof ASN1Encodable)) {
            return "unknown object type " + obj.toString();
        } else {
            primitive = ((ASN1Encodable) obj).toASN1Primitive();
        }
        StringBuffer buf = new StringBuffer();
        _dumpAsString("", verbose, primitive, buf);
        return buf.toString();
    }

    private static String dumpBinaryDataAsString(String indent, byte[] bytes) {
        String nl = Strings.lineSeparator();
        StringBuffer buf = new StringBuffer();
        String indent2 = indent + TAB;
        buf.append(nl);
        for (int i = 0; i < bytes.length; i += 32) {
            if (bytes.length - i > 32) {
                buf.append(indent2);
                buf.append(Strings.fromByteArray(Hex.encode(bytes, i, 32)));
                buf.append(TAB);
                buf.append(calculateAscString(bytes, i, 32));
                buf.append(nl);
            } else {
                buf.append(indent2);
                buf.append(Strings.fromByteArray(Hex.encode(bytes, i, bytes.length - i)));
                for (int j = bytes.length - i; j != 32; j++) {
                    buf.append("  ");
                }
                buf.append(TAB);
                buf.append(calculateAscString(bytes, i, bytes.length - i));
                buf.append(nl);
            }
        }
        return buf.toString();
    }

    private static String calculateAscString(byte[] bytes, int off, int len) {
        StringBuffer buf = new StringBuffer();
        for (int i = off; i != off + len; i++) {
            if (bytes[i] >= 32 && bytes[i] <= 126) {
                buf.append((char) bytes[i]);
            }
        }
        return buf.toString();
    }
}
