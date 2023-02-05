package com.mi.car.jsse.easysec.jce;

import com.mi.car.jsse.easysec.asn1.ASN1ObjectIdentifier;
import com.mi.car.jsse.easysec.asn1.cryptopro.ECGOST3410NamedCurves;
import com.mi.car.jsse.easysec.asn1.x9.X9ECParameters;
import com.mi.car.jsse.easysec.jce.spec.ECNamedCurveParameterSpec;
import java.util.Enumeration;

public class ECGOST3410NamedCurveTable {
    public static ECNamedCurveParameterSpec getParameterSpec(String name) {
        X9ECParameters ecP = ECGOST3410NamedCurves.getByNameX9(name);
        if (ecP == null) {
            try {
                ecP = ECGOST3410NamedCurves.getByOIDX9(new ASN1ObjectIdentifier(name));
            } catch (IllegalArgumentException e) {
                return null;
            }
        }
        if (ecP == null) {
            return null;
        }
        return new ECNamedCurveParameterSpec(name, ecP.getCurve(), ecP.getG(), ecP.getN(), ecP.getH(), ecP.getSeed());
    }

    public static Enumeration getNames() {
        return ECGOST3410NamedCurves.getNames();
    }
}
