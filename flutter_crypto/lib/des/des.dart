import 'dart:convert';

import 'package:fluttercrypto/util/crypto_util.dart';
import 'package:fluttercrypto/util/number_utils.dart';
import 'package:fluttercrypto/util/padding.dart';

/// author: karedem
/// 参考至: https://blog.csdn.net/yxtxiaotian/article/details/52025653
/// 以及 https://www.cnblogs.com/songwenlong/p/5944139.html
///
class DES {
  static const String _iv = '01234567';
  static const BLOCK_SIZE = 8;

  static const E_box = [
    //E
    32, 1, 2, 3, 4, 5, 4, 5, 6, 7, 8, 9,
    8, 9, 10, 11, 12, 13, 12, 13, 14, 15, 16, 17,
    16, 17, 18, 19, 20, 21, 20, 21, 22, 23, 24, 25,
    24, 25, 26, 27, 28, 29, 28, 29, 30, 31, 32, 1
  ];

  static const IP = [
    //IP
    58, 50, 42, 34, 26, 18, 10, 2, 60, 52, 44, 36, 28, 20, 12, 4,
    62, 54, 46, 38, 30, 22, 14, 6, 64, 56, 48, 40, 32, 24, 16, 8,
    57, 49, 41, 33, 25, 17, 9, 1, 59, 51, 43, 35, 27, 19, 11, 3,
    61, 53, 45, 37, 29, 21, 13, 5, 63, 55, 47, 39, 31, 23, 15, 7
  ];

  static const IP_1 = [
    //IP_R
    40, 8, 48, 16, 56, 24, 64, 32, 39, 7, 47, 15, 55, 23, 63, 31,
    38, 6, 46, 14, 54, 22, 62, 30, 37, 5, 45, 13, 53, 21, 61, 29,
    36, 4, 44, 12, 52, 20, 60, 28, 35, 3, 43, 11, 51, 19, 59, 27,
    34, 2, 42, 10, 50, 18, 58, 26, 33, 1, 41, 9, 49, 17, 57, 25
  ];

  static const PC_1 = [
    //PC_1
    57, 49, 41, 33, 25, 17, 9, 1, 58, 50, 42, 34, 26, 18,
    10, 2, 59, 51, 43, 35, 27, 19, 11, 3, 60, 52, 44, 36,
    63, 55, 47, 39, 31, 23, 15, 7, 62, 54, 46, 38, 30, 22,
    14, 6, 61, 53, 45, 37, 29, 21, 13, 5, 28, 20, 12, 4
  ];

  static const PC_2 = [
    //PC_2
    14, 17, 11, 24, 1, 5, 3, 28, 15, 6, 21, 10,
    23, 19, 12, 4, 26, 8, 16, 7, 27, 20, 13, 2,
    41, 52, 31, 37, 47, 55, 30, 40, 51, 45, 33, 48,
    44, 49, 39, 56, 34, 53, 46, 42, 50, 36, 29, 32
  ];

  static const S_Box = [
    [
      // S1
      14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7,
      0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8,
      4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0,
      15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13
    ],
    [
      //S2
      15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10,
      3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5,
      0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15,
      13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9
    ],
    [
      //S3
      10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8,
      13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1,
      13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7,
      1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12
    ],
    [
      //S4
      7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15,
      13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9,
      10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4,
      3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14
    ],
    [
      //S5
      2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9,
      14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6,
      4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14,
      11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3
    ],
    [
      //S6
      12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11,
      10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8,
      9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6,
      4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13
    ],
    [
      //S7
      4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1,
      13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6,
      1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2,
      6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12
    ],
    [
      //S8
      13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7,
      1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2,
      7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8,
      2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11
    ]
  ];

  static const P_Box = [
    //P_box
    16, 7, 20, 21,
    29, 12, 28, 17,
    1, 15, 23, 26,
    5, 18, 31, 10,
    2, 8, 24, 14,
    32, 27, 3, 9,
    19, 13, 30, 6,
    22, 11, 4, 25
  ];

  static const shift_digit = [1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1];

  ///将64字节的密钥压缩成56字节  字节数组转为二进制数组
  List<int> _compressKeyTo56(List<int> key) {
    List<int> bitKey = [];
    for (int i = 0; i < PC_1.length; i++) {
      int realIndex = PC_1[i] - 1;
      bitKey.add(NumberUtils.to8Bit(key[realIndex ~/ 8])[realIndex % 8]);
    }
    return bitKey;
  }

  ///离散得到16个子密钥
  List<List<int>> dispareKey(List<int> compressKey) {
    List<List<int>> dispareKeys = [];
    List<int> c0 = compressKey.sublist(0, 28);
    List<int> d0 = compressKey.sublist(28);
    List<int> tempc = c0;
    List<int> tempd = d0;
    for (int i = 0; i < 16; i++) {
      tempc = left_shift(i, tempc);
      tempd = left_shift(i, tempd);
      List<int> tempAll = [];
      tempAll.addAll(tempc);
      tempAll.addAll(tempd);

      List<int> dispareKey = compressDispareKey(tempAll);
      dispareKeys.add(dispareKey);
    }
    return dispareKeys;
  }

  ///左移函数  需要根据次数 左移
  static List<int> left_shift(int times, List<int> key) {
    ///需移动的位数
    int shift_length = shift_digit[times];
    List<int> newList = key.sublist(shift_length);
    newList.addAll(key.sublist(0, shift_length));
    return newList;
  }

  ///将56位的密钥压缩为48位 二进制数组 处理
  List<int> compressDispareKey(List<int> dispareKey) {
    List<int> bitKey = [];
    for (int i = 0; i < PC_2.length; i++) {
      int realIndex = PC_2[i] - 1;
      bitKey.add(dispareKey[realIndex]);
    }
    return bitKey;
  }

  ///明文转换  字节数组转二进制数组
  List<int> compressPlain(List<int> plain) {
    List<int> bitKey = [];
    for (int i = 0; i < IP.length; i++) {
      int realIndex = IP[i] - 1;
      bitKey.add(NumberUtils.to8Bit(plain[realIndex ~/ 8])[realIndex % 8]);
    }
    return bitKey;
  }

  ///E盒扩展
  List<int> E_transform(List<int> list) {
    ///左半部分为 L0  右半部分为R0
    //print("before E transform : " + list.toString());
    List<int> result = [];
    for (int i = 0; i < E_box.length; i++) {
      result.add(list[E_box[i] - 1]);
    }
    return result;
  }

  ///P盒置换
  List<int> P_transform(List<int> list) {
    List<int> bitKey = [];
    for (int i = 0; i < P_Box.length; i++) {
      int realIndex = P_Box[i] - 1;
      bitKey.add(list[realIndex]);
    }
    return bitKey;
  }

  ///S盒变换 二进制结果
  List<int> _S_Box_transform(List<int> list) {
    ///check list length 48
    List<int> result = [];
    for (int i = 0; i < list.length; i += 6) {
      int y = NumberUtils.intFromBits([list[i], list[i + 5]]);
      int x = NumberUtils.intFromBits(list.sublist(i + 1, i + 5));
      int i_n = S_Box[i ~/ 6][y * 16 + x];
      result.addAll(NumberUtils.to4Bit(i_n));
    }
    return result;
  }

  ///P盒置换的结果盒L0做异或
  List<int> _XOR_with_Left(List<int> left, List<int> presult) {
    List<int> result = [];
    for (int i = 0; i < left.length; i++) {
      result.add(left[i] ^ presult[i]);
    }
    return result;
  }

  ///IP_1置换
  List<int> _IP_1_transform(List<int> list) {
    ///check list length 48
    List<int> bitKey = [];
    for (int i = 0; i < IP_1.length; i++) {
      int realIndex = IP_1[i] - 1;
      bitKey.add(list[realIndex]);
    }
    return bitKey;
  }

  ///加密 明文asc字符串   密钥十六进制数
  List<int> encrypHexWithEcb(String hexPlain, String hexKey) {
    var plain = CryptoUtil.hex2List(hexPlain);
    var key = CryptoUtil.hex2List(hexKey);
    return encrypWithEcb(plain, key);
  }

  ///加密   明文字节数组  密钥字节数组
  List<int> encryptBlock(List<int> block, List<int> key) {
    List<List<int>> dispareKeys = [];
    List<int> pc1_key = _compressKeyTo56(key);
    //print("pc1_key " + pc1_key.toString());
    dispareKeys = dispareKey(pc1_key);

    ///dispareKey right!

    var plainCompressed = compressPlain(block);
    //print("plainCompressed " + plainCompressed.toString());
    List<int> L0 = plainCompressed.sublist(0, 32);
    List<int> R0 = plainCompressed.sublist(32);
    List<int> L0Z = L0;
    List<int> R0Z = R0;

    for (int i = 0; i < 16; i++) {
      var ln = R0Z;
      var pResult = P_transform(
          _S_Box_transform(_XOR_with_Left(dispareKeys[i], E_transform(R0Z))));
      var rn = _XOR_with_Left(pResult, L0Z);
      L0Z = ln;
      R0Z = rn;
    }
    List<int> result = [];
    result.addAll(R0Z);
    result.addAll(L0Z);
    result = _IP_1_transform(result);
    return NumberUtils.intListFromBits(result);
  }

  String encryptToHex(String plain, String key, {String iv = _iv}) {
    return CryptoUtil.list2Hex(encryptWithCBC(
        Utf8Encoder().convert(plain).toList(), key.codeUnits,
        iv: iv));
  }

  String decryptFromHex(String cipher, String key, {String iv = _iv}) {
    return Utf8Decoder().convert(
        decryptWithCBC(CryptoUtil.hex2List(cipher), key.codeUnits, iv: iv));
  }

  List<int> encryptWithCBC(List<int> plain, List<int> key, {String iv = _iv}) {
    List<int> blockCipher = [];
    int allLen = plain.length;
    int blockCount = allLen ~/ 8;
    List<int> padPlain = plain.sublist(0, 8 * blockCount);
    padPlain.addAll(Padding.pkcs7Padding(plain.sublist(8 * blockCount)));
    List<int> tempIv = iv.codeUnits;
    for (int i = 0; i < padPlain.length; i += BLOCK_SIZE) {
      List<int> xorPlain =
          _XOR_with_Left(padPlain.sublist(i, i + BLOCK_SIZE), tempIv);
      tempIv = encryptBlock(xorPlain, key);
      blockCipher.addAll(tempIv);
    }
    return blockCipher;
  }

  List<int> decryptWithCBC(List<int> cipher, List<int> key, {String iv = _iv}) {
    List<int> plain = [];
    List<int> tempIv = iv.codeUnits;
    for (int i = 0; i < cipher.length; i += BLOCK_SIZE) {
      if (i == cipher.length - BLOCK_SIZE) {
        List<int> plainXor =
            decryptBlock(cipher.sublist(i, i + BLOCK_SIZE), key);
        List<int> plainBlock =
            Padding.pkcs7UnPadding(_XOR_with_Left(plainXor, tempIv));
        tempIv = cipher.sublist(i, i + BLOCK_SIZE);
        plain.addAll(plainBlock);
      } else {
        List<int> plainXor =
            decryptBlock(cipher.sublist(i, i + BLOCK_SIZE), key);
        List<int> plainBlock = _XOR_with_Left(plainXor, tempIv);
        tempIv = cipher.sublist(i, i + BLOCK_SIZE);
        plain.addAll(plainBlock);
      }
    }
    return plain;
  }

  ///加密   明文字节数组  密钥字节数组
  List<int> encrypWithEcb(List<int> plain, List<int> key) {
    List<int> blockCipher = [];
    int allLen = plain.length;
    int blockCount = allLen ~/ 8;
    List<int> padPlain = plain.sublist(0, 8 * blockCount);
    padPlain.addAll(Padding.pkcs7Padding(plain.sublist(8 * blockCount)));
    for (int i = 0; i < padPlain.length; i += BLOCK_SIZE) {
      blockCipher
          .addAll(encryptBlock(padPlain.sublist(i, i + BLOCK_SIZE), key));
    }
    return blockCipher;
  }

  List<int> decryptBlock(List<int> cipher, List<int> key) {
    List<List<int>> dispareKeys = [];
    List<int> pc1_key = _compressKeyTo56(key);
    dispareKeys = dispareKey(pc1_key);

    var plainCompressed = compressPlain(cipher);
    List<int> L0 = plainCompressed.sublist(0, plainCompressed.length ~/ 2);
    List<int> R0 = plainCompressed.sublist(plainCompressed.length ~/ 2);
    List<int> L0Z = L0;
    List<int> R0Z = R0;
    for (int i = 0; i < 16; i++) {
      var ln = R0Z;
      var pResult = P_transform(_S_Box_transform(
          _XOR_with_Left(dispareKeys[15 - i], E_transform(R0Z))));
      var rn = _XOR_with_Left(pResult, L0Z);
      L0Z = ln;
      R0Z = rn;
    }
    List<int> result = [];
    result.addAll(R0Z);
    result.addAll(L0Z);
    result = _IP_1_transform(result);
    return NumberUtils.intListFromBits(result);
  }

  ///支持长数据解密
  List<int> decryptWithEcb(List<int> cipher, List<int> key) {
    List<int> plain = [];
    for (int i = 0; i < cipher.length; i += BLOCK_SIZE) {
      if (i == cipher.length - BLOCK_SIZE) {
        plain.addAll(Padding.pkcs7UnPadding(
            decryptBlock(cipher.sublist(i, i + BLOCK_SIZE), key)));
      } else {
        plain.addAll(decryptBlock(cipher.sublist(i, i + BLOCK_SIZE), key));
      }
    }
    return plain;
  }
}
