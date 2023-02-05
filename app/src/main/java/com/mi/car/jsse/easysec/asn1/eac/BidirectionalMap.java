package com.mi.car.jsse.easysec.asn1.eac;

import java.util.Hashtable;

public class BidirectionalMap extends Hashtable {
    private static final long serialVersionUID = -7457289971962812909L;
    Hashtable reverseMap = new Hashtable();

    public Object getReverse(Object o) {
        return this.reverseMap.get(o);
    }

    @Override // java.util.Map, java.util.Hashtable, java.util.Dictionary
    public Object put(Object key, Object o) {
        this.reverseMap.put(o, key);
        return super.put(key, o);
    }
}
