package com.mi.car.jsse.easysec.tls;

import com.mi.car.jsse.easysec.tls.crypto.SRP6Group;
import com.mi.car.jsse.easysec.tls.crypto.SRP6StandardGroups;
import com.mi.car.jsse.easysec.tls.crypto.TlsSRPConfig;
import java.math.BigInteger;
import java.util.Vector;

public class DefaultTlsSRPConfigVerifier implements TlsSRPConfigVerifier {
    private static final Vector DEFAULT_GROUPS = new Vector();
    protected final Vector groups;

    static {
        DEFAULT_GROUPS.addElement(SRP6StandardGroups.rfc5054_1024);
        DEFAULT_GROUPS.addElement(SRP6StandardGroups.rfc5054_1536);
        DEFAULT_GROUPS.addElement(SRP6StandardGroups.rfc5054_2048);
        DEFAULT_GROUPS.addElement(SRP6StandardGroups.rfc5054_3072);
        DEFAULT_GROUPS.addElement(SRP6StandardGroups.rfc5054_4096);
        DEFAULT_GROUPS.addElement(SRP6StandardGroups.rfc5054_6144);
        DEFAULT_GROUPS.addElement(SRP6StandardGroups.rfc5054_8192);
    }

    public DefaultTlsSRPConfigVerifier() {
        this(DEFAULT_GROUPS);
    }

    public DefaultTlsSRPConfigVerifier(Vector groups2) {
        this.groups = new Vector(groups2);
    }

    @Override // com.mi.car.jsse.easysec.tls.TlsSRPConfigVerifier
    public boolean accept(TlsSRPConfig srpConfig) {
        for (int i = 0; i < this.groups.size(); i++) {
            if (areGroupsEqual(srpConfig, (SRP6Group) this.groups.elementAt(i))) {
                return true;
            }
        }
        return false;
    }

    /* access modifiers changed from: protected */
    public boolean areGroupsEqual(TlsSRPConfig a, SRP6Group b) {
        BigInteger[] ng = a.getExplicitNG();
        return areParametersEqual(ng[0], b.getN()) && areParametersEqual(ng[1], b.getG());
    }

    /* access modifiers changed from: protected */
    public boolean areParametersEqual(BigInteger a, BigInteger b) {
        return a == b || a.equals(b);
    }
}
