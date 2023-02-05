package com.mi.car.jsse.easysec.crypto.generators;

import com.mi.car.jsse.easysec.crypto.Digest;

public class KDF2BytesGenerator extends BaseKDFBytesGenerator {
    public KDF2BytesGenerator(Digest digest) {
        super(1, digest);
    }
}
