package com.backend.auth.apikeys.apikey;

/**
 * Which deployment a key belongs to, visible in its prefix. A {@code test} key pasted into a production
 * client fails on the format check, and secret scanners can tell how urgent a leaked key is.
 */
public enum KeyEnvironment {

    LIVE("ak_live_"),
    TEST("ak_test_");

    private final String prefix;

    KeyEnvironment(String prefix) {
        this.prefix = prefix;
    }

    public String prefix() {
        return prefix;
    }
}
