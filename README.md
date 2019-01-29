Build status: [![build_status](https://travis-ci.org/sndr-oss/quickxorhash-java.svg?branch=master)](https://travis-ci.org/sndr-oss/quickxorhash-java)
# quickxorhash-java
Java MessageDigestSpi implementation of the proprietary Quick XOR Hash for Microsoft OneDrive for Business.

# Quick Start
To add this provider at runtime use:
<pre>
    import java.security.Security;
    import com.sndr.crypto.provider.QuickXorHashProvider;
    Security.addProvider(new QuickXorHashProvider());
</pre>
