package com.mi.car.jsse.easysec.asn1.x9;

import com.mi.car.jsse.easysec.asn1.ASN1ObjectIdentifier;
import com.mi.car.jsse.easysec.asn1.anssi.ANSSINamedCurves;
import com.mi.car.jsse.easysec.asn1.cryptlib.CryptlibObjectIdentifiers;
import com.mi.car.jsse.easysec.asn1.cryptopro.ECGOST3410NamedCurves;
import com.mi.car.jsse.easysec.asn1.gm.GMNamedCurves;
import com.mi.car.jsse.easysec.asn1.nist.NISTNamedCurves;
import com.mi.car.jsse.easysec.asn1.sec.SECNamedCurves;
import com.mi.car.jsse.easysec.asn1.teletrust.TeleTrusTNamedCurves;
import com.mi.car.jsse.easysec.crypto.ec.CustomNamedCurves;
import java.util.Enumeration;
import java.util.Vector;

public class ECNamedCurveTable {
    public static X9ECParameters getByName(String name) {
        X9ECParameters ecP = X962NamedCurves.getByName(name);
        if (ecP == null) {
            ecP = SECNamedCurves.getByName(name);
        }
        if (ecP == null) {
            ecP = NISTNamedCurves.getByName(name);
        }
        if (ecP == null) {
            ecP = TeleTrusTNamedCurves.getByName(name);
        }
        if (ecP == null) {
            ecP = ANSSINamedCurves.getByName(name);
        }
        if (ecP == null) {
            ecP = ECGOST3410NamedCurves.getByNameX9(name);
        }
        if (ecP == null) {
            return GMNamedCurves.getByName(name);
        }
        return ecP;
    }

    public static X9ECParametersHolder getByNameLazy(String name) {
        X9ECParametersHolder holder = X962NamedCurves.getByNameLazy(name);
        if (holder == null) {
            holder = SECNamedCurves.getByNameLazy(name);
        }
        if (holder == null) {
            holder = NISTNamedCurves.getByNameLazy(name);
        }
        if (holder == null) {
            holder = TeleTrusTNamedCurves.getByNameLazy(name);
        }
        if (holder == null) {
            holder = ANSSINamedCurves.getByNameLazy(name);
        }
        if (holder == null) {
            holder = ECGOST3410NamedCurves.getByNameLazy(name);
        }
        if (holder == null) {
            return GMNamedCurves.getByNameLazy(name);
        }
        return holder;
    }

    public static ASN1ObjectIdentifier getOID(String name) {
        ASN1ObjectIdentifier oid = X962NamedCurves.getOID(name);
        if (oid == null) {
            oid = SECNamedCurves.getOID(name);
        }
        if (oid == null) {
            oid = NISTNamedCurves.getOID(name);
        }
        if (oid == null) {
            oid = TeleTrusTNamedCurves.getOID(name);
        }
        if (oid == null) {
            oid = ANSSINamedCurves.getOID(name);
        }
        if (oid == null) {
            oid = ECGOST3410NamedCurves.getOID(name);
        }
        if (oid == null) {
            oid = GMNamedCurves.getOID(name);
        }
        if (oid != null || !name.equals("curve25519")) {
            return oid;
        }
        return CryptlibObjectIdentifiers.curvey25519;
    }

    public static String getName(ASN1ObjectIdentifier oid) {
        String name = X962NamedCurves.getName(oid);
        if (name == null) {
            name = SECNamedCurves.getName(oid);
        }
        if (name == null) {
            name = NISTNamedCurves.getName(oid);
        }
        if (name == null) {
            name = TeleTrusTNamedCurves.getName(oid);
        }
        if (name == null) {
            name = ANSSINamedCurves.getName(oid);
        }
        if (name == null) {
            name = ECGOST3410NamedCurves.getName(oid);
        }
        if (name == null) {
            name = GMNamedCurves.getName(oid);
        }
        if (name == null) {
            return CustomNamedCurves.getName(oid);
        }
        return name;
    }

    public static X9ECParameters getByOID(ASN1ObjectIdentifier oid) {
        X9ECParameters ecP = X962NamedCurves.getByOID(oid);
        if (ecP == null) {
            ecP = SECNamedCurves.getByOID(oid);
        }
        if (ecP == null) {
            ecP = TeleTrusTNamedCurves.getByOID(oid);
        }
        if (ecP == null) {
            ecP = ANSSINamedCurves.getByOID(oid);
        }
        if (ecP == null) {
            ecP = ECGOST3410NamedCurves.getByOIDX9(oid);
        }
        if (ecP == null) {
            return GMNamedCurves.getByOID(oid);
        }
        return ecP;
    }

    public static X9ECParametersHolder getByOIDLazy(ASN1ObjectIdentifier oid) {
        X9ECParametersHolder holder = X962NamedCurves.getByOIDLazy(oid);
        if (holder == null) {
            holder = SECNamedCurves.getByOIDLazy(oid);
        }
        if (holder == null) {
            holder = TeleTrusTNamedCurves.getByOIDLazy(oid);
        }
        if (holder == null) {
            holder = ANSSINamedCurves.getByOIDLazy(oid);
        }
        if (holder == null) {
            holder = ECGOST3410NamedCurves.getByOIDLazy(oid);
        }
        if (holder == null) {
            return GMNamedCurves.getByOIDLazy(oid);
        }
        return holder;
    }

    public static Enumeration getNames() {
        Vector v = new Vector();
        addEnumeration(v, X962NamedCurves.getNames());
        addEnumeration(v, SECNamedCurves.getNames());
        addEnumeration(v, NISTNamedCurves.getNames());
        addEnumeration(v, TeleTrusTNamedCurves.getNames());
        addEnumeration(v, ANSSINamedCurves.getNames());
        addEnumeration(v, ECGOST3410NamedCurves.getNames());
        addEnumeration(v, GMNamedCurves.getNames());
        return v.elements();
    }

    private static void addEnumeration(Vector v, Enumeration e) {
        while (e.hasMoreElements()) {
            v.addElement(e.nextElement());
        }
    }
}
