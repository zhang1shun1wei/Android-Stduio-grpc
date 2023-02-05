package com.mi.car.jsse.easysec.crypto.generators;

import com.mi.car.jsse.easysec.crypto.Digest;

public class KDF1BytesGenerator extends BaseKDFBytesGenerator {
    public KDF1BytesGenerator(Digest digest) {
        super(0, digest);
    }
}
