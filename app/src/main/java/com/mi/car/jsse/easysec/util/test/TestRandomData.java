package com.mi.car.jsse.easysec.util.test;

import com.mi.car.jsse.easysec.util.encoders.Hex;
import com.mi.car.jsse.easysec.util.test.FixedSecureRandom;

public class TestRandomData extends FixedSecureRandom {
    public TestRandomData(String encoding) {
        super(new Source[]{new Data(Hex.decode(encoding))});
    }

    public TestRandomData(byte[] encoding) {
        super(new Source[]{new Data(encoding)});
    }
}
