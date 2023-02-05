package com.mi.car.jsse.easysec.asn1.anssi;

import com.mi.car.jsse.easysec.asn1.ASN1ObjectIdentifier;
import com.mi.car.jsse.easysec.asn1.x9.X9ECParameters;
import com.mi.car.jsse.easysec.asn1.x9.X9ECParametersHolder;
import com.mi.car.jsse.easysec.asn1.x9.X9ECPoint;
import com.mi.car.jsse.easysec.math.ec.ECCurve;
import com.mi.car.jsse.easysec.math.ec.WNafUtil;
import com.mi.car.jsse.easysec.util.Strings;
import com.mi.car.jsse.easysec.util.encoders.Hex;
import java.math.BigInteger;
import java.util.Enumeration;
import java.util.Hashtable;

public class ANSSINamedCurves {
    static X9ECParametersHolder FRP256v1 = new X9ECParametersHolder() {
        public ECCurve createCurve() {
            BigInteger p = ANSSINamedCurves.fromHex("F1FD178C0B3AD58F10126DE8CE42435B3961ADBCABC8CA6DE8FCF353D86E9C03");
            BigInteger a = ANSSINamedCurves.fromHex("F1FD178C0B3AD58F10126DE8CE42435B3961ADBCABC8CA6DE8FCF353D86E9C00");
            BigInteger b = ANSSINamedCurves.fromHex("EE353FCA5428A9300D4ABA754A44C00FDFEC0C9AE4B1A1803075ED967B7BB73F");
            BigInteger n = ANSSINamedCurves.fromHex("F1FD178C0B3AD58F10126DE8CE42435B53DC67E140D2BF941FFDD459C6D655E1");
            BigInteger h = BigInteger.valueOf(1L);
            return ANSSINamedCurves.configureCurve(new ECCurve.Fp(p, a, b, n, h, true));
        }

        public X9ECParameters createParameters() {
            byte[] S = null;
            ECCurve curve = this.createCurve();
            X9ECPoint G = ANSSINamedCurves.configureBasepoint(curve, "04B6B3D4C356C139EB31183D4749D423958C27D2DCAF98B70164C97A2DD98F5CFF6142E0F7C8B204911F9271F0F3ECEF8C2701C307E8E4C9E183115A1554062CFB");
            return new X9ECParameters(curve, G, curve.getOrder(), curve.getCofactor(), (byte[])S);
        }
    };
    static final Hashtable objIds = new Hashtable();
    static final Hashtable curves = new Hashtable();
    static final Hashtable names = new Hashtable();

    public ANSSINamedCurves() {
    }

    private static X9ECPoint configureBasepoint(ECCurve curve, String encoding) {
        X9ECPoint G = new X9ECPoint(curve, Hex.decodeStrict(encoding));
        WNafUtil.configureBasepoint(G.getPoint());
        return G;
    }

    private static ECCurve configureCurve(ECCurve curve) {
        return curve;
    }

    private static BigInteger fromHex(String hex) {
        return new BigInteger(1, Hex.decodeStrict(hex));
    }

    static void defineCurve(String name, ASN1ObjectIdentifier oid, X9ECParametersHolder holder) {
        objIds.put(Strings.toLowerCase(name), oid);
        names.put(oid, name);
        curves.put(oid, holder);
    }

    public static X9ECParameters getByName(String name) {
        ASN1ObjectIdentifier oid = getOID(name);
        return oid == null ? null : getByOID(oid);
    }

    public static X9ECParametersHolder getByNameLazy(String name) {
        ASN1ObjectIdentifier oid = getOID(name);
        return oid == null ? null : getByOIDLazy(oid);
    }

    public static X9ECParameters getByOID(ASN1ObjectIdentifier oid) {
        X9ECParametersHolder holder = getByOIDLazy(oid);
        return holder == null ? null : holder.getParameters();
    }

    public static X9ECParametersHolder getByOIDLazy(ASN1ObjectIdentifier oid) {
        return (X9ECParametersHolder)curves.get(oid);
    }

    public static ASN1ObjectIdentifier getOID(String name) {
        return (ASN1ObjectIdentifier)objIds.get(Strings.toLowerCase(name));
    }

    public static String getName(ASN1ObjectIdentifier oid) {
        return (String)names.get(oid);
    }

    public static Enumeration getNames() {
        return names.elements();
    }

    static {
        defineCurve("FRP256v1", ANSSIObjectIdentifiers.FRP256v1, FRP256v1);
    }
}
