library pbkdf2;

import 'package:crypto/crypto.dart';
import 'dart:async';

class PBKDF2 {
  Hash hash;
  List<int> _blockList = new List<int>(4);

  PBKDF2({Hash this.hash});

  Future<List<int>> generateKey(String password, String salt, int c, int dkLen) async {

    var digestSize = hash.convert([1,2,3]).bytes.length;

    if (dkLen > (4294967295 /*(2<<31)-1*/) * digestSize) {
      return new Future.error("derived key too long");
    }

    var numberOfBlocks = (dkLen / digestSize).ceil();
    var sizeOfLastBlock = dkLen - (numberOfBlocks - 1) * digestSize;

    var key = [];
    for (var i = 1; i <= numberOfBlocks; i++) {
      var block = await _computeBlock(password, salt, c, i);
      if (i < numberOfBlocks) {
        key.addAll(block);
      } else {
        key.addAll(block.sublist(0, sizeOfLastBlock));
      }
    }
    return key;
  }

  Future<List<int>> _computeBlock(String password, String salt, int iterations, int blockNumber) async {
    var hmac = new Hmac(hash, password.codeUnits);
    var digestStream = new StreamController<Digest>();
    var hmacSink = hmac.startChunkedConversion(digestStream);

    hmacSink.add(salt.codeUnits);
    _writeBlockNumber(hmacSink, blockNumber);
    hmacSink.close();
    var lastDigest = await digestStream.stream.first;

    var result = lastDigest.bytes;
    for (var i = 1; i < iterations; i++) {
      hmac = new Hmac(hash, password.codeUnits);
      digestStream = new StreamController<Digest>();
      hmacSink = hmac.startChunkedConversion(digestStream);
      hmacSink.add(lastDigest.bytes);
      hmacSink.close();

      var newDigest = await digestStream.stream.first;
      _xorLists(result, newDigest.bytes);
      lastDigest = newDigest;
    }
    return result;
  }

  _writeBlockNumber(var hmacSink, int blockNumber) {
    _blockList[0] = blockNumber >> 24;
    _blockList[1] = blockNumber >> 16;
    _blockList[2] = blockNumber >> 8;
    _blockList[3] = blockNumber;
    hmacSink.add(_blockList);
  }

  _xorLists(List<int> list1, List<int> list2) {
    for (var i = 0; i < list1.length; i++) {
      list1[i] = list1[i] ^ list2[i];
    }
  }
}
