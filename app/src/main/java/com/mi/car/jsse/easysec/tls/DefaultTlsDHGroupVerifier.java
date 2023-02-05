package com.mi.car.jsse.easysec.tls;

import com.mi.car.jsse.easysec.tls.crypto.DHGroup;
import com.mi.car.jsse.easysec.tls.crypto.DHStandardGroups;
import java.math.BigInteger;
import java.util.Vector;

public class DefaultTlsDHGroupVerifier implements TlsDHGroupVerifier {
    private static final Vector DEFAULT_GROUPS = new Vector();
    public static final int DEFAULT_MINIMUM_PRIME_BITS = 2048;
    protected Vector groups;
    protected int minimumPrimeBits;

    static {
        addDefaultGroup(DHStandardGroups.rfc3526_2048);
        addDefaultGroup(DHStandardGroups.rfc3526_3072);
        addDefaultGroup(DHStandardGroups.rfc3526_4096);
        addDefaultGroup(DHStandardGroups.rfc3526_6144);
        addDefaultGroup(DHStandardGroups.rfc3526_8192);
        addDefaultGroup(DHStandardGroups.rfc7919_ffdhe2048);
        addDefaultGroup(DHStandardGroups.rfc7919_ffdhe3072);
        addDefaultGroup(DHStandardGroups.rfc7919_ffdhe4096);
        addDefaultGroup(DHStandardGroups.rfc7919_ffdhe6144);
        addDefaultGroup(DHStandardGroups.rfc7919_ffdhe8192);
    }

    private static void addDefaultGroup(DHGroup dhGroup) {
        DEFAULT_GROUPS.addElement(dhGroup);
    }

    public DefaultTlsDHGroupVerifier() {
        this(DEFAULT_MINIMUM_PRIME_BITS);
    }

    public DefaultTlsDHGroupVerifier(int minimumPrimeBits2) {
        this(DEFAULT_GROUPS, minimumPrimeBits2);
    }

    public DefaultTlsDHGroupVerifier(Vector groups2, int minimumPrimeBits2) {
        this.groups = new Vector(groups2);
        this.minimumPrimeBits = minimumPrimeBits2;
    }

    @Override // com.mi.car.jsse.easysec.tls.TlsDHGroupVerifier
    public boolean accept(DHGroup dhGroup) {
        return checkMinimumPrimeBits(dhGroup) && checkGroup(dhGroup);
    }

    public int getMinimumPrimeBits() {
        return this.minimumPrimeBits;
    }

    /* access modifiers changed from: protected */
    public boolean areGroupsEqual(DHGroup a, DHGroup b) {
        return a == b || (areParametersEqual(a.getP(), b.getP()) && areParametersEqual(a.getG(), b.getG()));
    }

    /* access modifiers changed from: protected */
    public boolean areParametersEqual(BigInteger a, BigInteger b) {
        return a == b || a.equals(b);
    }

    /* access modifiers changed from: protected */
    public boolean checkGroup(DHGroup dhGroup) {
        for (int i = 0; i < this.groups.size(); i++) {
            if (areGroupsEqual(dhGroup, (DHGroup) this.groups.elementAt(i))) {
                return true;
            }
        }
        return false;
    }

    /* access modifiers changed from: protected */
    public boolean checkMinimumPrimeBits(DHGroup dhGroup) {
        return dhGroup.getP().bitLength() >= getMinimumPrimeBits();
    }
}
