library pbkdf2;

import 'package:crypto/crypto.dart';
import 'dart:convert';

// Reference https://tools.ietf.org/html/rfc2898#page-9
class PBKDF2 {
  Hash hash;
  List<int> _blockList = new List<int>(4);

  PBKDF2({this.hash});

  List<int> generateKey(String password, String salt, int c, int dkLen) {
    if (dkLen > (2 << 31 - 1) * prfLengthInBytes) {
      throw "derived key too long";
    }

    var numberOfBlocks = (dkLen / prfLengthInBytes).ceil();
    var sizeOfLastBlock = dkLen - (numberOfBlocks - 1) * prfLengthInBytes;

    var key = <int>[];
    for (var i = 1; i <= numberOfBlocks; ++i) {
      var block = _computeBlock(password, salt, c, i);
      if (i < numberOfBlocks) {
        key.addAll(block);
      } else {
        key.addAll(block.sublist(0, sizeOfLastBlock));
      }
    }
    return key;
  }

  int get prfLengthInBytes {
    var digest = hash.convert([1, 2, 3]);
    var digestLength = digest.bytes.length;
    return digestLength;
  }

  List<int> _computeBlock(
      String password, String salt, int iterations, int blockNumber) {
    var hmac = new Hmac(hash, password.codeUnits);
    var sink = new SyncChunkedConversionSink();
    var outsink = hmac.startChunkedConversion(sink);

    outsink.add(salt.codeUnits);

    _writeBlockNumber(outsink, blockNumber);

    outsink.close();
    sink.close();

    var bytes = sink.getAll();
    var lastDigest = bytes;
    var result = new List.from(bytes);

    for (var i = 1; i < iterations; i++) {
      hmac = new Hmac(hash, password.codeUnits);
      var newDigest = hmac.convert(lastDigest);

      _xorLists(result, newDigest.bytes);

      lastDigest = newDigest.bytes;
    }

    return result;
  }

  void _writeBlockNumber(ByteConversionSink hmac, int blockNumber) {
    _blockList[0] = blockNumber >> 24;
    _blockList[1] = blockNumber >> 16;
    _blockList[2] = blockNumber >> 8;
    _blockList[3] = blockNumber;
    hmac.add(_blockList);
  }

  void _xorLists(List<int> list1, List<int> list2) {
    for (var i = 0; i < list1.length; i++) {
      list1[i] = list1[i] ^ list2[i];
    }
  }
}

class SyncChunkedConversionSink extends ChunkedConversionSink<Digest> {
  final List<Digest> accumulated = <Digest>[];

  @override
  void add(Digest chunk) {
    accumulated.add(chunk);
  }

  @override
  void close() {}

  List<int> getAll() =>
      accumulated.fold([], (acc, current) => acc..addAll(current.bytes));
}
