import 'package:pbkdf2/pbkdf2.dart';
import 'package:unittest/unittest.dart';
import 'package:crypto/crypto.dart';

List<int> encodeBytes(String bytes) {
  var byteList = bytes.split(" ");
  var result = [];
  for (var byte in byteList) {
    result.add(int.parse(byte, radix: 16));
  }
  return result;
}

main() {
  group("PBKDF2", () {
    test("Should disallow large values of dkLen", () {
      var sha = new SHA1();
      sha.add([1]);
      var hLen = sha.close().length;
      var gen = new PBKDF2(hash: sha);
      expect(() => gen.generateKey("password", "salt", 1, ((2 << 31) - 1) * hLen + 1), throws);
    });

    test("Should work with RFC6070 test vectors 1", () {
      var gen = new PBKDF2(hash: new SHA1());
      var output = gen.generateKey("password", "salt", 1, 20);
      expect(output, encodeBytes("0c 60 c8 0f 96 1f 0e 71 f3 a9 b5 24 af 60 12 06 2f e0 37 a6"));
    });

    test("Should work with RFC6070 test vectors 2", () {
      var gen = new PBKDF2(hash: new SHA1());
      var output = gen.generateKey("password", "salt", 2, 20);
      expect(output, encodeBytes("ea 6c 01 4d c7 2d 6f 8c cd 1e d9 2a ce 1d 41 f0 d8 de 89 57"));
    });

    test("Should work with RFC6070 test vectors 3", () {
      var gen = new PBKDF2(hash: new SHA1());
      var output = gen.generateKey("password", "salt", 4096, 20);
      expect(output, encodeBytes("4b 00 79 01 b7 65 48 9a be ad 49 d9 26 f7 21 d0 65 a4 29 c1"));
    });

    // This test may take a few minutes to run
    test("Should work with RFC6070 test vectors 4", () {
      var gen = new PBKDF2(hash: new SHA1());
      var output = gen.generateKey("password", "salt", 16777216, 20);
      expect(output, encodeBytes("ee fe 3d 61 cd 4d a4 e4 e9 94 5b 3d 6b a2 15 8c 26 34 e9 84"));
    });

    test("Should work with RFC6070 test vectors 5", () {
      var gen = new PBKDF2(hash: new SHA1());
      var output = gen.generateKey("passwordPASSWORDpassword", "saltSALTsaltSALTsaltSALTsaltSALTsalt", 4096, 25);
      expect(output, encodeBytes("3d 2e ec 4f e4 1c 84 9b 80 c8 d8 36 62 c0 e4 4a 8b 29 1a 96 4c f2 f0 70 38"));
    });

    test("Should work with RFC6070 test vectors 6", () {
      var gen = new PBKDF2(hash: new SHA1());
      var output = gen.generateKey("pass\u0000word", "sa\u0000lt", 4096, 16);
      expect(output, encodeBytes("56 fa 6a a7 55 48 09 9d cc 37 d7 f0 34 25 e0 c3"));
    });
  });
}