package com.mi.car.jsse.easysec.asn1.x509;

import com.mi.car.jsse.easysec.asn1.ASN1Encodable;
import com.mi.car.jsse.easysec.asn1.ASN1EncodableVector;
import com.mi.car.jsse.easysec.asn1.ASN1Encoding;
import com.mi.car.jsse.easysec.asn1.ASN1Object;
import com.mi.car.jsse.easysec.asn1.ASN1ObjectIdentifier;
import com.mi.car.jsse.easysec.asn1.ASN1Primitive;
import com.mi.car.jsse.easysec.asn1.ASN1Sequence;
import com.mi.car.jsse.easysec.asn1.ASN1Set;
import com.mi.car.jsse.easysec.asn1.ASN1String;
import com.mi.car.jsse.easysec.asn1.ASN1TaggedObject;
import com.mi.car.jsse.easysec.asn1.ASN1UniversalString;
import com.mi.car.jsse.easysec.asn1.DERSequence;
import com.mi.car.jsse.easysec.asn1.DERSet;
import com.mi.car.jsse.easysec.asn1.pkcs.PKCSObjectIdentifiers;
import com.mi.car.jsse.easysec.asn1.x500.X500Name;
import com.mi.car.jsse.easysec.util.Strings;
import com.mi.car.jsse.easysec.util.encoders.Hex;
import java.io.IOException;
import java.util.Enumeration;
import java.util.Hashtable;
import java.util.Vector;

public class X509Name extends ASN1Object {
    public static final ASN1ObjectIdentifier BUSINESS_CATEGORY = new ASN1ObjectIdentifier("2.5.4.15");
    public static final ASN1ObjectIdentifier C = new ASN1ObjectIdentifier("2.5.4.6");
    public static final ASN1ObjectIdentifier CN = new ASN1ObjectIdentifier("2.5.4.3");
    public static final ASN1ObjectIdentifier COUNTRY_OF_CITIZENSHIP = new ASN1ObjectIdentifier("1.3.6.1.5.5.7.9.4");
    public static final ASN1ObjectIdentifier COUNTRY_OF_RESIDENCE = new ASN1ObjectIdentifier("1.3.6.1.5.5.7.9.5");
    public static final ASN1ObjectIdentifier DATE_OF_BIRTH = new ASN1ObjectIdentifier("1.3.6.1.5.5.7.9.1");
    public static final ASN1ObjectIdentifier DC = new ASN1ObjectIdentifier("0.9.2342.19200300.100.1.25");
    public static final ASN1ObjectIdentifier DMD_NAME = new ASN1ObjectIdentifier("2.5.4.54");
    public static final ASN1ObjectIdentifier DN_QUALIFIER = new ASN1ObjectIdentifier("2.5.4.46");
    public static final Hashtable DefaultLookUp = new Hashtable();
    public static boolean DefaultReverse = false;
    public static final Hashtable DefaultSymbols = new Hashtable();
    public static final ASN1ObjectIdentifier EmailAddress = PKCSObjectIdentifiers.pkcs_9_at_emailAddress;
    public static final ASN1ObjectIdentifier E = EmailAddress;
    private static final Boolean FALSE = new Boolean(false);
    public static final ASN1ObjectIdentifier GENDER = new ASN1ObjectIdentifier("1.3.6.1.5.5.7.9.3");
    public static final ASN1ObjectIdentifier GENERATION = new ASN1ObjectIdentifier("2.5.4.44");
    public static final ASN1ObjectIdentifier GIVENNAME = new ASN1ObjectIdentifier("2.5.4.42");
    public static final ASN1ObjectIdentifier INITIALS = new ASN1ObjectIdentifier("2.5.4.43");
    public static final ASN1ObjectIdentifier L = new ASN1ObjectIdentifier("2.5.4.7");
    public static final ASN1ObjectIdentifier NAME = X509ObjectIdentifiers.id_at_name;
    public static final ASN1ObjectIdentifier NAME_AT_BIRTH = new ASN1ObjectIdentifier("1.3.36.8.3.14");
    public static final ASN1ObjectIdentifier O = new ASN1ObjectIdentifier("2.5.4.10");
    public static final Hashtable OIDLookUp = DefaultSymbols;
    public static final ASN1ObjectIdentifier OU = new ASN1ObjectIdentifier("2.5.4.11");
    public static final ASN1ObjectIdentifier PLACE_OF_BIRTH = new ASN1ObjectIdentifier("1.3.6.1.5.5.7.9.2");
    public static final ASN1ObjectIdentifier POSTAL_ADDRESS = new ASN1ObjectIdentifier("2.5.4.16");
    public static final ASN1ObjectIdentifier POSTAL_CODE = new ASN1ObjectIdentifier("2.5.4.17");
    public static final ASN1ObjectIdentifier PSEUDONYM = new ASN1ObjectIdentifier("2.5.4.65");
    public static final Hashtable RFC1779Symbols = new Hashtable();
    public static final Hashtable RFC2253Symbols = new Hashtable();
    public static final ASN1ObjectIdentifier SN = new ASN1ObjectIdentifier("2.5.4.5");
    public static final ASN1ObjectIdentifier SERIALNUMBER = SN;
    public static final ASN1ObjectIdentifier ST = new ASN1ObjectIdentifier("2.5.4.8");
    public static final ASN1ObjectIdentifier STREET = new ASN1ObjectIdentifier("2.5.4.9");
    public static final ASN1ObjectIdentifier SURNAME = new ASN1ObjectIdentifier("2.5.4.4");
    public static final Hashtable SymbolLookUp = DefaultLookUp;
    public static final ASN1ObjectIdentifier T = new ASN1ObjectIdentifier("2.5.4.12");
    public static final ASN1ObjectIdentifier TELEPHONE_NUMBER = X509ObjectIdentifiers.id_at_telephoneNumber;
    private static final Boolean TRUE = new Boolean(true);
    public static final ASN1ObjectIdentifier UID = new ASN1ObjectIdentifier("0.9.2342.19200300.100.1.1");
    public static final ASN1ObjectIdentifier UNIQUE_IDENTIFIER = new ASN1ObjectIdentifier("2.5.4.45");
    public static final ASN1ObjectIdentifier UnstructuredAddress = PKCSObjectIdentifiers.pkcs_9_at_unstructuredAddress;
    public static final ASN1ObjectIdentifier UnstructuredName = PKCSObjectIdentifiers.pkcs_9_at_unstructuredName;
    private Vector added;
    private X509NameEntryConverter converter;
    private int hashCodeValue;
    private boolean isHashCodeCalculated;
    private Vector ordering;
    private ASN1Sequence seq;
    private Vector values;

    static {
        DefaultSymbols.put(C, "C");
        DefaultSymbols.put(O, "O");
        DefaultSymbols.put(T, "T");
        DefaultSymbols.put(OU, "OU");
        DefaultSymbols.put(CN, "CN");
        DefaultSymbols.put(L, "L");
        DefaultSymbols.put(ST, "ST");
        DefaultSymbols.put(SN, "SERIALNUMBER");
        DefaultSymbols.put(EmailAddress, "E");
        DefaultSymbols.put(DC, "DC");
        DefaultSymbols.put(UID, "UID");
        DefaultSymbols.put(STREET, "STREET");
        DefaultSymbols.put(SURNAME, "SURNAME");
        DefaultSymbols.put(GIVENNAME, "GIVENNAME");
        DefaultSymbols.put(INITIALS, "INITIALS");
        DefaultSymbols.put(GENERATION, "GENERATION");
        DefaultSymbols.put(UnstructuredAddress, "unstructuredAddress");
        DefaultSymbols.put(UnstructuredName, "unstructuredName");
        DefaultSymbols.put(UNIQUE_IDENTIFIER, "UniqueIdentifier");
        DefaultSymbols.put(DN_QUALIFIER, "DN");
        DefaultSymbols.put(PSEUDONYM, "Pseudonym");
        DefaultSymbols.put(POSTAL_ADDRESS, "PostalAddress");
        DefaultSymbols.put(NAME_AT_BIRTH, "NameAtBirth");
        DefaultSymbols.put(COUNTRY_OF_CITIZENSHIP, "CountryOfCitizenship");
        DefaultSymbols.put(COUNTRY_OF_RESIDENCE, "CountryOfResidence");
        DefaultSymbols.put(GENDER, "Gender");
        DefaultSymbols.put(PLACE_OF_BIRTH, "PlaceOfBirth");
        DefaultSymbols.put(DATE_OF_BIRTH, "DateOfBirth");
        DefaultSymbols.put(POSTAL_CODE, "PostalCode");
        DefaultSymbols.put(BUSINESS_CATEGORY, "BusinessCategory");
        DefaultSymbols.put(TELEPHONE_NUMBER, "TelephoneNumber");
        DefaultSymbols.put(NAME, "Name");
        RFC2253Symbols.put(C, "C");
        RFC2253Symbols.put(O, "O");
        RFC2253Symbols.put(OU, "OU");
        RFC2253Symbols.put(CN, "CN");
        RFC2253Symbols.put(L, "L");
        RFC2253Symbols.put(ST, "ST");
        RFC2253Symbols.put(STREET, "STREET");
        RFC2253Symbols.put(DC, "DC");
        RFC2253Symbols.put(UID, "UID");
        RFC1779Symbols.put(C, "C");
        RFC1779Symbols.put(O, "O");
        RFC1779Symbols.put(OU, "OU");
        RFC1779Symbols.put(CN, "CN");
        RFC1779Symbols.put(L, "L");
        RFC1779Symbols.put(ST, "ST");
        RFC1779Symbols.put(STREET, "STREET");
        DefaultLookUp.put("c", C);
        DefaultLookUp.put("o", O);
        DefaultLookUp.put("t", T);
        DefaultLookUp.put("ou", OU);
        DefaultLookUp.put("cn", CN);
        DefaultLookUp.put("l", L);
        DefaultLookUp.put("st", ST);
        DefaultLookUp.put("sn", SN);
        DefaultLookUp.put("serialnumber", SN);
        DefaultLookUp.put("street", STREET);
        DefaultLookUp.put("emailaddress", E);
        DefaultLookUp.put("dc", DC);
        DefaultLookUp.put("e", E);
        DefaultLookUp.put("uid", UID);
        DefaultLookUp.put("surname", SURNAME);
        DefaultLookUp.put("givenname", GIVENNAME);
        DefaultLookUp.put("initials", INITIALS);
        DefaultLookUp.put("generation", GENERATION);
        DefaultLookUp.put("unstructuredaddress", UnstructuredAddress);
        DefaultLookUp.put("unstructuredname", UnstructuredName);
        DefaultLookUp.put("uniqueidentifier", UNIQUE_IDENTIFIER);
        DefaultLookUp.put("dn", DN_QUALIFIER);
        DefaultLookUp.put("pseudonym", PSEUDONYM);
        DefaultLookUp.put("postaladdress", POSTAL_ADDRESS);
        DefaultLookUp.put("nameofbirth", NAME_AT_BIRTH);
        DefaultLookUp.put("countryofcitizenship", COUNTRY_OF_CITIZENSHIP);
        DefaultLookUp.put("countryofresidence", COUNTRY_OF_RESIDENCE);
        DefaultLookUp.put("gender", GENDER);
        DefaultLookUp.put("placeofbirth", PLACE_OF_BIRTH);
        DefaultLookUp.put("dateofbirth", DATE_OF_BIRTH);
        DefaultLookUp.put("postalcode", POSTAL_CODE);
        DefaultLookUp.put("businesscategory", BUSINESS_CATEGORY);
        DefaultLookUp.put("telephonenumber", TELEPHONE_NUMBER);
        DefaultLookUp.put("name", NAME);
    }

    public static X509Name getInstance(ASN1TaggedObject obj, boolean explicit) {
        return getInstance(ASN1Sequence.getInstance(obj, explicit));
    }

    public static X509Name getInstance(Object obj) {
        if (obj instanceof X509Name) {
            return (X509Name) obj;
        }
        if (obj instanceof X500Name) {
            return new X509Name(ASN1Sequence.getInstance(((X500Name) obj).toASN1Primitive()));
        }
        if (obj != null) {
            return new X509Name(ASN1Sequence.getInstance(obj));
        }
        return null;
    }

    protected X509Name() {
        this.converter = null;
        this.ordering = new Vector();
        this.values = new Vector();
        this.added = new Vector();
    }

    public X509Name(ASN1Sequence seq2) {
        Boolean bool;
        this.converter = null;
        this.ordering = new Vector();
        this.values = new Vector();
        this.added = new Vector();
        this.seq = seq2;
        Enumeration e = seq2.getObjects();
        while (e.hasMoreElements()) {
            ASN1Set set = ASN1Set.getInstance(((ASN1Encodable) e.nextElement()).toASN1Primitive());
            int i = 0;
            while (true) {
                if (i < set.size()) {
                    ASN1Sequence s = ASN1Sequence.getInstance(set.getObjectAt(i).toASN1Primitive());
                    if (s.size() != 2) {
                        throw new IllegalArgumentException("badly sized pair");
                    }
                    this.ordering.addElement(ASN1ObjectIdentifier.getInstance(s.getObjectAt(0)));
                    ASN1Encodable value = s.getObjectAt(1);
                    if (!(value instanceof ASN1String) || (value instanceof ASN1UniversalString)) {
                        try {
                            this.values.addElement("#" + bytesToString(Hex.encode(value.toASN1Primitive().getEncoded(ASN1Encoding.DER))));
                        } catch (IOException e2) {
                            throw new IllegalArgumentException("cannot encode value");
                        }
                    } else {
                        String v = ((ASN1String) value).getString();
                        if (v.length() <= 0 || v.charAt(0) != '#') {
                            this.values.addElement(v);
                        } else {
                            this.values.addElement("\\" + v);
                        }
                    }
                    Vector vector = this.added;
                    if (i != 0) {
                        bool = TRUE;
                    } else {
                        bool = FALSE;
                    }
                    vector.addElement(bool);
                    i++;
                }
            }
        }
    }

    public X509Name(Hashtable attributes) {
        this((Vector) null, attributes);
    }

    public X509Name(Vector ordering2, Hashtable attributes) {
        this(ordering2, attributes, new X509DefaultEntryConverter());
    }

    public X509Name(Vector ordering2, Hashtable attributes, X509NameEntryConverter converter2) {
        this.converter = null;
        this.ordering = new Vector();
        this.values = new Vector();
        this.added = new Vector();
        this.converter = converter2;
        if (ordering2 != null) {
            for (int i = 0; i != ordering2.size(); i++) {
                this.ordering.addElement(ordering2.elementAt(i));
                this.added.addElement(FALSE);
            }
        } else {
            Enumeration e = attributes.keys();
            while (e.hasMoreElements()) {
                this.ordering.addElement(e.nextElement());
                this.added.addElement(FALSE);
            }
        }
        for (int i2 = 0; i2 != this.ordering.size(); i2++) {
            ASN1ObjectIdentifier oid = (ASN1ObjectIdentifier) this.ordering.elementAt(i2);
            if (attributes.get(oid) == null) {
                throw new IllegalArgumentException("No attribute for object id - " + oid.getId() + " - passed to distinguished name");
            }
            this.values.addElement(attributes.get(oid));
        }
    }

    public X509Name(Vector oids, Vector values2) {
        this(oids, values2, new X509DefaultEntryConverter());
    }

    public X509Name(Vector oids, Vector values2, X509NameEntryConverter converter2) {
        this.converter = null;
        this.ordering = new Vector();
        this.values = new Vector();
        this.added = new Vector();
        this.converter = converter2;
        if (oids.size() != values2.size()) {
            throw new IllegalArgumentException("oids vector must be same length as values.");
        }
        for (int i = 0; i < oids.size(); i++) {
            this.ordering.addElement(oids.elementAt(i));
            this.values.addElement(values2.elementAt(i));
            this.added.addElement(FALSE);
        }
    }

    public X509Name(String dirName) {
        this(DefaultReverse, DefaultLookUp, dirName);
    }

    public X509Name(String dirName, X509NameEntryConverter converter2) {
        this(DefaultReverse, DefaultLookUp, dirName, converter2);
    }

    public X509Name(boolean reverse, String dirName) {
        this(reverse, DefaultLookUp, dirName);
    }

    public X509Name(boolean reverse, String dirName, X509NameEntryConverter converter2) {
        this(reverse, DefaultLookUp, dirName, converter2);
    }

    public X509Name(boolean reverse, Hashtable lookUp, String dirName) {
        this(reverse, lookUp, dirName, new X509DefaultEntryConverter());
    }

    private ASN1ObjectIdentifier decodeOID(String name, Hashtable lookUp) {
        String name2 = name.trim();
        if (Strings.toUpperCase(name2).startsWith("OID.")) {
            return new ASN1ObjectIdentifier(name2.substring(4));
        }
        if (name2.charAt(0) >= '0' && name2.charAt(0) <= '9') {
            return new ASN1ObjectIdentifier(name2);
        }
        ASN1ObjectIdentifier oid = (ASN1ObjectIdentifier) lookUp.get(Strings.toLowerCase(name2));
        if (oid != null) {
            return oid;
        }
        throw new IllegalArgumentException("Unknown object id - " + name2 + " - passed to distinguished name");
    }

    private String unescape(String elt) {
        if (elt.length() == 0 || (elt.indexOf(92) < 0 && elt.indexOf(34) < 0)) {
            return elt.trim();
        }
        char[] elts = elt.toCharArray();
        boolean escaped = false;
        boolean quoted = false;
        StringBuffer buf = new StringBuffer(elt.length());
        int start = 0;
        if (elts[0] == '\\' && elts[1] == '#') {
            start = 2;
            buf.append("\\#");
        }
        boolean nonWhiteSpaceEncountered = false;
        int lastEscaped = 0;
        for (int i = start; i != elts.length; i++) {
            char c = elts[i];
            if (c != ' ') {
                nonWhiteSpaceEncountered = true;
            }
            if (c == '\"') {
                if (!escaped) {
                    quoted = !quoted;
                } else {
                    buf.append(c);
                }
                escaped = false;
            } else if (c == '\\' && !escaped && !quoted) {
                escaped = true;
                lastEscaped = buf.length();
            } else if (c != ' ' || escaped || nonWhiteSpaceEncountered) {
                buf.append(c);
                escaped = false;
            }
        }
        if (buf.length() > 0) {
            while (buf.charAt(buf.length() - 1) == ' ' && lastEscaped != buf.length() - 1) {
                buf.setLength(buf.length() - 1);
            }
        }
        return buf.toString();
    }

    public X509Name(boolean reverse, Hashtable lookUp, String dirName, X509NameEntryConverter converter2) {
        this.converter = null;
        this.ordering = new Vector();
        this.values = new Vector();
        this.added = new Vector();
        this.converter = converter2;
        X509NameTokenizer nTok = new X509NameTokenizer(dirName);
        while (nTok.hasMoreTokens()) {
            String token = nTok.nextToken();
            if (token.indexOf(43) > 0) {
                X509NameTokenizer pTok = new X509NameTokenizer(token, '+');
                addEntry(lookUp, pTok.nextToken(), FALSE);
                while (pTok.hasMoreTokens()) {
                    addEntry(lookUp, pTok.nextToken(), TRUE);
                }
            } else {
                addEntry(lookUp, token, FALSE);
            }
        }
        if (reverse) {
            Vector o = new Vector();
            Vector v = new Vector();
            Vector a = new Vector();
            int count = 1;
            for (int i = 0; i < this.ordering.size(); i++) {
                if (((Boolean) this.added.elementAt(i)).booleanValue()) {
                    o.insertElementAt(this.ordering.elementAt(i), count);
                    v.insertElementAt(this.values.elementAt(i), count);
                    a.insertElementAt(this.added.elementAt(i), count);
                    count++;
                } else {
                    o.insertElementAt(this.ordering.elementAt(i), 0);
                    v.insertElementAt(this.values.elementAt(i), 0);
                    a.insertElementAt(this.added.elementAt(i), 0);
                    count = 1;
                }
            }
            this.ordering = o;
            this.values = v;
            this.added = a;
        }
    }

    private void addEntry(Hashtable lookUp, String token, Boolean isAdded) {
        X509NameTokenizer vTok = new X509NameTokenizer(token, '=');
        String name = vTok.nextToken();
        if (!vTok.hasMoreTokens()) {
            throw new IllegalArgumentException("badly formatted directory string");
        }
        String value = vTok.nextToken();
        this.ordering.addElement(decodeOID(name, lookUp));
        this.values.addElement(unescape(value));
        this.added.addElement(isAdded);
    }

    public Vector getOIDs() {
        Vector v = new Vector();
        for (int i = 0; i != this.ordering.size(); i++) {
            v.addElement(this.ordering.elementAt(i));
        }
        return v;
    }

    public Vector getValues() {
        Vector v = new Vector();
        for (int i = 0; i != this.values.size(); i++) {
            v.addElement(this.values.elementAt(i));
        }
        return v;
    }

    public Vector getValues(ASN1ObjectIdentifier oid) {
        Vector v = new Vector();
        for (int i = 0; i != this.values.size(); i++) {
            if (this.ordering.elementAt(i).equals(oid)) {
                String val = (String) this.values.elementAt(i);
                if (val.length() > 2 && val.charAt(0) == '\\' && val.charAt(1) == '#') {
                    v.addElement(val.substring(1));
                } else {
                    v.addElement(val);
                }
            }
        }
        return v;
    }

    @Override // com.mi.car.jsse.easysec.asn1.ASN1Object, com.mi.car.jsse.easysec.asn1.ASN1Encodable
    public ASN1Primitive toASN1Primitive() {
        if (this.seq == null) {
            ASN1EncodableVector vec = new ASN1EncodableVector();
            ASN1EncodableVector sVec = new ASN1EncodableVector();
            ASN1ObjectIdentifier lstOid = null;
            for (int i = 0; i != this.ordering.size(); i++) {
                ASN1EncodableVector v = new ASN1EncodableVector(2);
                ASN1ObjectIdentifier oid = (ASN1ObjectIdentifier) this.ordering.elementAt(i);
                v.add(oid);
                v.add(this.converter.getConvertedValue(oid, (String) this.values.elementAt(i)));
                if (lstOid == null || ((Boolean) this.added.elementAt(i)).booleanValue()) {
                    sVec.add(new DERSequence(v));
                } else {
                    vec.add(new DERSet(sVec));
                    sVec = new ASN1EncodableVector();
                    sVec.add(new DERSequence(v));
                }
                lstOid = oid;
            }
            vec.add(new DERSet(sVec));
            this.seq = new DERSequence(vec);
        }
        return this.seq;
    }

    public boolean equals(Object obj, boolean inOrder) {
        if (!inOrder) {
            return equals(obj);
        }
        if (obj == this) {
            return true;
        }
        if (!((obj instanceof X509Name) || (obj instanceof ASN1Sequence))) {
            return false;
        }
        if (toASN1Primitive().equals(((ASN1Encodable) obj).toASN1Primitive())) {
            return true;
        }
        try {
            X509Name other = getInstance(obj);
            int orderingSize = this.ordering.size();
            if (orderingSize != other.ordering.size()) {
                return false;
            }
            for (int i = 0; i < orderingSize; i++) {
                if (!((ASN1ObjectIdentifier) this.ordering.elementAt(i)).equals((ASN1Primitive) ((ASN1ObjectIdentifier) other.ordering.elementAt(i)))) {
                    return false;
                }
                if (!equivalentStrings((String) this.values.elementAt(i), (String) other.values.elementAt(i))) {
                    return false;
                }
            }
            return true;
        } catch (IllegalArgumentException e) {
            return false;
        }
    }

    @Override // com.mi.car.jsse.easysec.asn1.ASN1Object
    public int hashCode() {
        if (this.isHashCodeCalculated) {
            return this.hashCodeValue;
        }
        this.isHashCodeCalculated = true;
        for (int i = 0; i != this.ordering.size(); i++) {
            String value = stripInternalSpaces(canonicalize((String) this.values.elementAt(i)));
            this.hashCodeValue ^= this.ordering.elementAt(i).hashCode();
            this.hashCodeValue ^= value.hashCode();
        }
        return this.hashCodeValue;
    }

    @Override // com.mi.car.jsse.easysec.asn1.ASN1Object
    public boolean equals(Object obj) {
        int start;
        int end;
        int delta;
        if (obj == this) {
            return true;
        }
        if (!((obj instanceof X509Name) || (obj instanceof ASN1Sequence))) {
            return false;
        }
        if (toASN1Primitive().equals(((ASN1Encodable) obj).toASN1Primitive())) {
            return true;
        }
        try {
            X509Name other = getInstance(obj);
            int orderingSize = this.ordering.size();
            if (orderingSize != other.ordering.size()) {
                return false;
            }
            boolean[] indexes = new boolean[orderingSize];
            if (this.ordering.elementAt(0).equals(other.ordering.elementAt(0))) {
                start = 0;
                end = orderingSize;
                delta = 1;
            } else {
                start = orderingSize - 1;
                end = -1;
                delta = -1;
            }
            for (int i = start; i != end; i += delta) {
                boolean found = false;
                ASN1ObjectIdentifier oid = (ASN1ObjectIdentifier) this.ordering.elementAt(i);
                String value = (String) this.values.elementAt(i);
                int j = 0;
                while (true) {
                    if (j >= orderingSize) {
                        break;
                    } else if (!indexes[j] && oid.equals((ASN1Primitive) ((ASN1ObjectIdentifier) other.ordering.elementAt(j))) && equivalentStrings(value, (String) other.values.elementAt(j))) {
                        indexes[j] = true;
                        found = true;
                        break;
                    } else {
                        j++;
                    }
                }
                if (!found) {
                    return false;
                }
            }
            return true;
        } catch (IllegalArgumentException e) {
            return false;
        }
    }

    private boolean equivalentStrings(String s1, String s2) {
        String value = canonicalize(s1);
        String oValue = canonicalize(s2);
        if (value.equals(oValue) || stripInternalSpaces(value).equals(stripInternalSpaces(oValue))) {
            return true;
        }
        return false;
    }

    private String canonicalize(String s) {
        String value = Strings.toLowerCase(s.trim());
        if (value.length() <= 0 || value.charAt(0) != '#') {
            return value;
        }
        ASN1Primitive obj = decodeObject(value);
        if (obj instanceof ASN1String) {
            return Strings.toLowerCase(((ASN1String) obj).getString().trim());
        }
        return value;
    }

    private ASN1Primitive decodeObject(String oValue) {
        try {
            return ASN1Primitive.fromByteArray(Hex.decodeStrict(oValue, 1, oValue.length() - 1));
        } catch (IOException e) {
            throw new IllegalStateException("unknown encoding in name: " + e);
        }
    }

    private String stripInternalSpaces(String str) {
        StringBuffer res = new StringBuffer();
        if (str.length() != 0) {
            char c1 = str.charAt(0);
            res.append(c1);
            for (int k = 1; k < str.length(); k++) {
                char c2 = str.charAt(k);
                if (c1 != ' ' || c2 != ' ') {
                    res.append(c2);
                }
                c1 = c2;
            }
        }
        return res.toString();
    }

    /*  JADX ERROR: JadxRuntimeException in pass: BlockProcessor
        jadx.core.utils.exceptions.JadxRuntimeException: CFG modification limit reached, blocks count: 131
        	at jadx.core.dex.visitors.blocksmaker.BlockProcessor.processBlocksTree(BlockProcessor.java:72)
        	at jadx.core.dex.visitors.blocksmaker.BlockProcessor.visit(BlockProcessor.java:46)
        */
    private void appendValue(StringBuffer r8, Hashtable r9, ASN1ObjectIdentifier r10, String r11) {
        /*
        // Method dump skipped, instructions count: 152
        */
        throw new UnsupportedOperationException("Method not decompiled: com.mi.car.jsse.easysec.asn1.x509.X509Name.appendValue(java.lang.StringBuffer, java.util.Hashtable, com.mi.car.jsse.easysec.asn1.ASN1ObjectIdentifier, java.lang.String):void");
    }

    public String toString(boolean reverse, Hashtable oidSymbols) {
        StringBuffer buf = new StringBuffer();
        Vector components = new Vector();
        boolean first = true;
        StringBuffer ava = null;
        for (int i = 0; i < this.ordering.size(); i++) {
            if (((Boolean) this.added.elementAt(i)).booleanValue()) {
                ava.append('+');
                appendValue(ava, oidSymbols, (ASN1ObjectIdentifier) this.ordering.elementAt(i), (String) this.values.elementAt(i));
            } else {
                ava = new StringBuffer();
                appendValue(ava, oidSymbols, (ASN1ObjectIdentifier) this.ordering.elementAt(i), (String) this.values.elementAt(i));
                components.addElement(ava);
            }
        }
        if (reverse) {
            for (int i2 = components.size() - 1; i2 >= 0; i2--) {
                if (first) {
                    first = false;
                } else {
                    buf.append(',');
                }
                buf.append(components.elementAt(i2).toString());
            }
        } else {
            for (int i3 = 0; i3 < components.size(); i3++) {
                if (first) {
                    first = false;
                } else {
                    buf.append(',');
                }
                buf.append(components.elementAt(i3).toString());
            }
        }
        return buf.toString();
    }

    private String bytesToString(byte[] data) {
        char[] cs = new char[data.length];
        for (int i = 0; i != cs.length; i++) {
            cs[i] = (char) (data[i] & 255);
        }
        return new String(cs);
    }

    public String toString() {
        return toString(DefaultReverse, DefaultSymbols);
    }
}
