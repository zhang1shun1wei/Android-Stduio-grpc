package com.mi.car.jsse.easysec.i18n;

import java.io.UnsupportedEncodingException;
import java.util.Locale;
import java.util.TimeZone;

public class MessageBundle extends TextBundle {
    public static final String TITLE_ENTRY = "title";

    public MessageBundle(String resource, String id) throws NullPointerException {
        super(resource, id);
    }

    public MessageBundle(String resource, String id, String encoding) throws NullPointerException, UnsupportedEncodingException {
        super(resource, id, encoding);
    }

    public MessageBundle(String resource, String id, Object[] arguments) throws NullPointerException {
        super(resource, id, arguments);
    }

    public MessageBundle(String resource, String id, String encoding, Object[] arguments) throws NullPointerException, UnsupportedEncodingException {
        super(resource, id, encoding, arguments);
    }

    public String getTitle(Locale loc, TimeZone timezone) throws MissingEntryException {
        return getEntry(TITLE_ENTRY, loc, timezone);
    }

    public String getTitle(Locale loc) throws MissingEntryException {
        return getEntry(TITLE_ENTRY, loc, TimeZone.getDefault());
    }
}
