package com.mi.car.jsse.easysec.crypto.engines;

import com.mi.car.jsse.easysec.util.Memoable;

public final class Zuc128Engine extends Zuc128CoreEngine {
    public Zuc128Engine() {
    }

    private Zuc128Engine(Zuc128Engine pSource) {
        super(pSource);
    }

    @Override // com.mi.car.jsse.easysec.util.Memoable, com.mi.car.jsse.easysec.crypto.engines.Zuc128CoreEngine
    public Memoable copy() {
        return new Zuc128Engine(this);
    }
}
