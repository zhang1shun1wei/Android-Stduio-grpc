package com.mi.car.jsse.easysec.pqc.crypto.saber;

import com.mi.car.jsse.easysec.asn1.BERTags;
import com.mi.car.jsse.easysec.crypto.CipherParameters;

public class SABERParameters implements CipherParameters {
    public static final SABERParameters firesaberkem128r3 = new SABERParameters("firesaberkem128r3", 4, 128);
    public static final SABERParameters firesaberkem192r3 = new SABERParameters("firesaberkem192r3", 4, BERTags.PRIVATE);
    public static final SABERParameters firesaberkem256r3 = new SABERParameters("firesaberkem256r3", 4, 256);
    public static final SABERParameters lightsaberkem128r3 = new SABERParameters("lightsaberkem128r3", 2, 128);
    public static final SABERParameters lightsaberkem192r3 = new SABERParameters("lightsaberkem192r3", 2, BERTags.PRIVATE);
    public static final SABERParameters lightsaberkem256r3 = new SABERParameters("lightsaberkem256r3", 2, 256);
    public static final SABERParameters saberkem128r3 = new SABERParameters("saberkem128r3", 3, 128);
    public static final SABERParameters saberkem192r3 = new SABERParameters("saberkem192r3", 3, BERTags.PRIVATE);
    public static final SABERParameters saberkem256r3 = new SABERParameters("saberkem256r3", 3, 256);
    private final int defaultKeySize;
    private final SABEREngine engine;
    private final int l;
    private final String name;

    public SABERParameters(String name2, int l2, int defaultKeySize2) {
        this.name = name2;
        this.l = l2;
        this.defaultKeySize = defaultKeySize2;
        this.engine = new SABEREngine(l2, defaultKeySize2);
    }

    public String getName() {
        return this.name;
    }

    public int getL() {
        return this.l;
    }

    public int getDefaultKeySize() {
        return this.defaultKeySize;
    }

    public SABEREngine getEngine() {
        return this.engine;
    }
}
