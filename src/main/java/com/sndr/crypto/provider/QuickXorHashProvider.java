package com.sndr.crypto.provider;

import java.security.Provider;

/**
 * MessageDigest provider for Microsoft's QuickXorHash algorithm.
 *
 * To add this provider at runtime use:
 * <pre>
 *     import java.security.Security;
 *     import com.sndr.crypto.provider.QuickXorHashProvider;
 *
 *     Security.addProvider(new QuickXorHashProvider());
 * </pre>
 */
public class QuickXorHashProvider extends Provider {
    private static final String PROVIDER_NAME = "QuickXorHash Provider";
    private static final double PROVIDER_VERSION = 1.0;
    private static final String PROVIDER_INFO = "Implementation of Microsoft's QuickXorHash algorithm.";
    private static final String PROVIDER_KEY = "MessageDigest.QuickXorHash";
    private static final String PROVIDER_VALUE = "com.sndr.crypto.provider.QuickXorHashDigest";

    /**
     * Constructor for the Provider that sets the name, version, and info.
     * Also adds the Provider to the security manager.
     */
    public QuickXorHashProvider() {
        super(PROVIDER_NAME, PROVIDER_VERSION, PROVIDER_INFO);
        put(PROVIDER_KEY, PROVIDER_VALUE);
    }
}
