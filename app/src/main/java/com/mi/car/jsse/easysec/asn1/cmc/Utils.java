//
// Source code recreated from a .class file by IntelliJ IDEA
// (powered by FernFlower decompiler)
//

package com.mi.car.jsse.easysec.asn1.cmc;

import com.mi.car.jsse.easysec.asn1.ASN1Sequence;
import com.mi.car.jsse.easysec.asn1.x509.Extension;

class Utils {
    Utils() {
    }

    static BodyPartID[] toBodyPartIDArray(ASN1Sequence bodyPartIDs) {
        BodyPartID[] ids = new BodyPartID[bodyPartIDs.size()];

        for(int i = 0; i != bodyPartIDs.size(); ++i) {
            ids[i] = BodyPartID.getInstance(bodyPartIDs.getObjectAt(i));
        }

        return ids;
    }

    static BodyPartID[] clone(BodyPartID[] ids) {
        BodyPartID[] tmp = new BodyPartID[ids.length];
        System.arraycopy(ids, 0, tmp, 0, ids.length);
        return tmp;
    }

    static Extension[] clone(Extension[] ids) {
        Extension[] tmp = new Extension[ids.length];
        System.arraycopy(ids, 0, tmp, 0, ids.length);
        return tmp;
    }
}