pbkdf2
======

This is an implementation of the PBKDF2 key derivation function, as defined
in [RFC 2898](http://tools.ietf.org/html/rfc2898).

Usage
-----

    // Create PBKDF2 instance using the SHA256 hash. The default is to use SHA1
    var gen = new PBKDF2(hash: new SHA256());

    // Generate a 32 byte key using the given password and salt, with 1000 iterations
    var key = gen.generateKey("password", "salt", 1000, 32);
