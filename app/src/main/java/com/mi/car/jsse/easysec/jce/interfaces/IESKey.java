package com.mi.car.jsse.easysec.jce.interfaces;

import java.security.Key;
import java.security.PrivateKey;
import java.security.PublicKey;

public interface IESKey extends Key {
    PrivateKey getPrivate();

    PublicKey getPublic();
}
