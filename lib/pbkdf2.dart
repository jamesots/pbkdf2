library pbkdf2;

import 'package:crypto/crypto.dart';

class PBKDF2 {
  Hash hash;
  List<int> _blockList = new List<int>(4);

  PBKDF2({this.hash});

  List<int> generateKey(String password, String salt, int c, int dkLen) {
    var blockSize = hash.convert([1, 2, 3]).bytes.length;
    if (dkLen > ((2 << 31) - 1) * blockSize) {
      throw "derived key too long";
    }

    var numberOfBlocks = (dkLen / blockSize).ceil();
    var sizeOfLastBlock = dkLen - (numberOfBlocks - 1) * blockSize;

    var key = <int>[];
    for (var i = 1; i <= numberOfBlocks; i++) {
      var block = _computeBlock(password, salt, c, i);
      if (i < numberOfBlocks) {
        key.addAll(block);
      } else {
        key.addAll(block.sublist(0, sizeOfLastBlock));
      }
    }
    return key;
  }

  List<int> _computeBlock(
      String password, String salt, int iterations, int blockNumber) {
    var hmac = new Hmac(hash, password.codeUnits);
    var list = new List<int>.from(salt.codeUnits);
    _writeBlockNumber(list, blockNumber);
    var lastDigest = hmac.convert(list).bytes;
    var result = lastDigest;
    for (var i = 1; i < iterations; i++) {
      hmac = new Hmac(hash, password.codeUnits);
      var newDigest = hmac.convert(lastDigest).bytes;
      _xorLists(result, newDigest);
      lastDigest = newDigest;
    }
    return result;
  }

  void _writeBlockNumber(List<int> list, int blockNumber) {
    _blockList[0] = blockNumber >> 24;
    _blockList[1] = blockNumber >> 16;
    _blockList[2] = blockNumber >> 8;
    _blockList[3] = blockNumber;
    list.addAll(_blockList);
  }

  void _xorLists(List<int> list1, List<int> list2) {
    for (var i = 0; i < list1.length; i++) {
      list1[i] = list1[i] ^ list2[i];
    }
  }
}
