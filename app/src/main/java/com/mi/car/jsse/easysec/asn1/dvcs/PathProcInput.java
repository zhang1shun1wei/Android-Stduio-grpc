package com.mi.car.jsse.easysec.asn1.dvcs;

import com.mi.car.jsse.easysec.asn1.ASN1Boolean;
import com.mi.car.jsse.easysec.asn1.ASN1Encodable;
import com.mi.car.jsse.easysec.asn1.ASN1EncodableVector;
import com.mi.car.jsse.easysec.asn1.ASN1Object;
import com.mi.car.jsse.easysec.asn1.ASN1Primitive;
import com.mi.car.jsse.easysec.asn1.ASN1Sequence;
import com.mi.car.jsse.easysec.asn1.ASN1TaggedObject;
import com.mi.car.jsse.easysec.asn1.DERSequence;
import com.mi.car.jsse.easysec.asn1.DERTaggedObject;
import com.mi.car.jsse.easysec.asn1.x509.PolicyInformation;
import java.util.Arrays;

public class PathProcInput extends ASN1Object {
    private PolicyInformation[] acceptablePolicySet;
    private boolean explicitPolicyReqd = false;
    private boolean inhibitAnyPolicy = false;
    private boolean inhibitPolicyMapping = false;

    public PathProcInput(PolicyInformation[] acceptablePolicySet2) {
        this.acceptablePolicySet = copy(acceptablePolicySet2);
    }

    public PathProcInput(PolicyInformation[] acceptablePolicySet2, boolean inhibitPolicyMapping2, boolean explicitPolicyReqd2, boolean inhibitAnyPolicy2) {
        this.acceptablePolicySet = copy(acceptablePolicySet2);
        this.inhibitPolicyMapping = inhibitPolicyMapping2;
        this.explicitPolicyReqd = explicitPolicyReqd2;
        this.inhibitAnyPolicy = inhibitAnyPolicy2;
    }

    private static PolicyInformation[] fromSequence(ASN1Sequence seq) {
        PolicyInformation[] tmp = new PolicyInformation[seq.size()];
        for (int i = 0; i != tmp.length; i++) {
            tmp[i] = PolicyInformation.getInstance(seq.getObjectAt(i));
        }
        return tmp;
    }

    public static PathProcInput getInstance(Object obj) {
        if (obj instanceof PathProcInput) {
            return (PathProcInput) obj;
        }
        if (obj == null) {
            return null;
        }
        ASN1Sequence seq = ASN1Sequence.getInstance(obj);
        PathProcInput result = new PathProcInput(fromSequence(ASN1Sequence.getInstance(seq.getObjectAt(0))));
        for (int i = 1; i < seq.size(); i++) {
            ASN1Encodable o = seq.getObjectAt(i);
            if (o instanceof ASN1Boolean) {
                result.setInhibitPolicyMapping(ASN1Boolean.getInstance(o).isTrue());
            } else if (o instanceof ASN1TaggedObject) {
                ASN1TaggedObject t = ASN1TaggedObject.getInstance(o);
                switch (t.getTagNo()) {
                    case 0:
                        result.setExplicitPolicyReqd(ASN1Boolean.getInstance(t, false).isTrue());
                        continue;
                    case 1:
                        result.setInhibitAnyPolicy(ASN1Boolean.getInstance(t, false).isTrue());
                        continue;
                    default:
                        throw new IllegalArgumentException("Unknown tag encountered: " + t.getTagNo());
                }
            } else {
                continue;
            }
        }
        return result;
    }

    public static PathProcInput getInstance(ASN1TaggedObject obj, boolean explicit) {
        return getInstance(ASN1Sequence.getInstance(obj, explicit));
    }

    public ASN1Primitive toASN1Primitive() {
        ASN1EncodableVector v = new ASN1EncodableVector(4);
        ASN1EncodableVector pV = new ASN1EncodableVector(this.acceptablePolicySet.length);
        for (int i = 0; i != this.acceptablePolicySet.length; i++) {
            pV.add(this.acceptablePolicySet[i]);
        }
        v.add(new DERSequence(pV));
        if (this.inhibitPolicyMapping) {
            v.add(ASN1Boolean.getInstance(this.inhibitPolicyMapping));
        }
        if (this.explicitPolicyReqd) {
            v.add(new DERTaggedObject(false, 0, ASN1Boolean.getInstance(this.explicitPolicyReqd)));
        }
        if (this.inhibitAnyPolicy) {
            v.add(new DERTaggedObject(false, 1, ASN1Boolean.getInstance(this.inhibitAnyPolicy)));
        }
        return new DERSequence(v);
    }

    public String toString() {
        return "PathProcInput: {\nacceptablePolicySet: " + Arrays.asList(this.acceptablePolicySet) + "\ninhibitPolicyMapping: " + this.inhibitPolicyMapping + "\nexplicitPolicyReqd: " + this.explicitPolicyReqd + "\ninhibitAnyPolicy: " + this.inhibitAnyPolicy + "\n}\n";
    }

    public PolicyInformation[] getAcceptablePolicySet() {
        return copy(this.acceptablePolicySet);
    }

    public boolean isInhibitPolicyMapping() {
        return this.inhibitPolicyMapping;
    }

    private void setInhibitPolicyMapping(boolean inhibitPolicyMapping2) {
        this.inhibitPolicyMapping = inhibitPolicyMapping2;
    }

    public boolean isExplicitPolicyReqd() {
        return this.explicitPolicyReqd;
    }

    private void setExplicitPolicyReqd(boolean explicitPolicyReqd2) {
        this.explicitPolicyReqd = explicitPolicyReqd2;
    }

    public boolean isInhibitAnyPolicy() {
        return this.inhibitAnyPolicy;
    }

    private void setInhibitAnyPolicy(boolean inhibitAnyPolicy2) {
        this.inhibitAnyPolicy = inhibitAnyPolicy2;
    }

    private PolicyInformation[] copy(PolicyInformation[] policySet) {
        PolicyInformation[] rv = new PolicyInformation[policySet.length];
        System.arraycopy(policySet, 0, rv, 0, rv.length);
        return rv;
    }
}
