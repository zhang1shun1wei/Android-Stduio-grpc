package com.mi.car.jsse.easysec.asn1.est;

class Utils {
    Utils() {
    }

    static AttrOrOID[] clone(AttrOrOID[] ids) {
        AttrOrOID[] tmp = new AttrOrOID[ids.length];
        System.arraycopy(ids, 0, tmp, 0, ids.length);
        return tmp;
    }
}
