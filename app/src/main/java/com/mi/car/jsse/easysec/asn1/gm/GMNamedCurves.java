package com.mi.car.jsse.easysec.asn1.gm;

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

public class GMNamedCurves {
    static final Hashtable curves = new Hashtable();
    static final Hashtable names = new Hashtable();
    static final Hashtable objIds = new Hashtable();
    static X9ECParametersHolder sm2p256v1 = new X9ECParametersHolder() {
        /* class com.mi.car.jsse.easysec.asn1.gm.GMNamedCurves.AnonymousClass1 */

        /* access modifiers changed from: protected */
        @Override // com.mi.car.jsse.easysec.asn1.x9.X9ECParametersHolder
        public ECCurve createCurve() {
            return GMNamedCurves.configureCurve(new ECCurve.Fp(GMNamedCurves.fromHex("FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF"), GMNamedCurves.fromHex("FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC"), GMNamedCurves.fromHex("28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93"), GMNamedCurves.fromHex("FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123"), BigInteger.valueOf(1), true));
        }

        /* access modifiers changed from: protected */
        @Override // com.mi.car.jsse.easysec.asn1.x9.X9ECParametersHolder
        public X9ECParameters createParameters() {
            ECCurve curve = getCurve();
            return new X9ECParameters(curve, GMNamedCurves.configureBasepoint(curve, "0432C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7BC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0"), curve.getOrder(), curve.getCofactor(), null);
        }
    };
    static X9ECParametersHolder wapip192v1 = new X9ECParametersHolder() {
        /* class com.mi.car.jsse.easysec.asn1.gm.GMNamedCurves.AnonymousClass2 */

        /* access modifiers changed from: protected */
        @Override // com.mi.car.jsse.easysec.asn1.x9.X9ECParametersHolder
        public ECCurve createCurve() {
            return GMNamedCurves.configureCurve(new ECCurve.Fp(GMNamedCurves.fromHex("BDB6F4FE3E8B1D9E0DA8C0D46F4C318CEFE4AFE3B6B8551F"), GMNamedCurves.fromHex("BB8E5E8FBC115E139FE6A814FE48AAA6F0ADA1AA5DF91985"), GMNamedCurves.fromHex("1854BEBDC31B21B7AEFC80AB0ECD10D5B1B3308E6DBF11C1"), GMNamedCurves.fromHex("BDB6F4FE3E8B1D9E0DA8C0D40FC962195DFAE76F56564677"), BigInteger.valueOf(1), true));
        }

        /* access modifiers changed from: protected */
        @Override // com.mi.car.jsse.easysec.asn1.x9.X9ECParametersHolder
        public X9ECParameters createParameters() {
            ECCurve curve = getCurve();
            return new X9ECParameters(curve, GMNamedCurves.configureBasepoint(curve, "044AD5F7048DE709AD51236DE65E4D4B482C836DC6E410664002BB3A02D4AAADACAE24817A4CA3A1B014B5270432DB27D2"), curve.getOrder(), curve.getCofactor(), null);
        }
    };

    /* access modifiers changed from: private */
    public static X9ECPoint configureBasepoint(ECCurve curve, String encoding) {
        X9ECPoint G = new X9ECPoint(curve, Hex.decodeStrict(encoding));
        WNafUtil.configureBasepoint(G.getPoint());
        return G;
    }

    /* access modifiers changed from: private */
    public static ECCurve configureCurve(ECCurve curve) {
        return curve;
    }

    /* access modifiers changed from: private */
    public static BigInteger fromHex(String hex) {
        return new BigInteger(1, Hex.decodeStrict(hex));
    }

    static {
        defineCurve("wapip192v1", GMObjectIdentifiers.wapip192v1, wapip192v1);
        defineCurve("sm2p256v1", GMObjectIdentifiers.sm2p256v1, sm2p256v1);
    }

    static void defineCurve(String name, ASN1ObjectIdentifier oid, X9ECParametersHolder holder) {
        objIds.put(Strings.toLowerCase(name), oid);
        names.put(oid, name);
        curves.put(oid, holder);
    }

    public static X9ECParameters getByName(String name) {
        ASN1ObjectIdentifier oid = getOID(name);
        if (oid == null) {
            return null;
        }
        return getByOID(oid);
    }

    public static X9ECParametersHolder getByNameLazy(String name) {
        ASN1ObjectIdentifier oid = getOID(name);
        if (oid == null) {
            return null;
        }
        return getByOIDLazy(oid);
    }

    public static X9ECParameters getByOID(ASN1ObjectIdentifier oid) {
        X9ECParametersHolder holder = getByOIDLazy(oid);
        if (holder == null) {
            return null;
        }
        return holder.getParameters();
    }

    public static X9ECParametersHolder getByOIDLazy(ASN1ObjectIdentifier oid) {
        return (X9ECParametersHolder) curves.get(oid);
    }

    public static ASN1ObjectIdentifier getOID(String name) {
        return (ASN1ObjectIdentifier) objIds.get(Strings.toLowerCase(name));
    }

    public static String getName(ASN1ObjectIdentifier oid) {
        return (String) names.get(oid);
    }

    public static Enumeration getNames() {
        return names.elements();
    }
}
