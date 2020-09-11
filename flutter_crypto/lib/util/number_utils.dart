import 'dart:math';

class NumberUtils {
  ///二进制数组转字节数组
  static List<int> intListFromBits(List<int> bits) {
    List<int> result = [];
    for (int i = 0; i < bits.length; i += 8) {
      if (i + 8 > bits.length) {
        break;
      }
      result.add(intFromBits(bits.sublist(i, i + 8)));
    }
    return result;
  }

  ///字节数组转二进制数组
  static List<int> bitsFromIntList(List<int> ints) {
    List<int> result = [];
    ints.forEach((i) {
      result.addAll(to8Bit(i));
    });
    return result;
  }

  ///二进制字符串转数字
  static int intFromBits(List<int> bits) {
    int result = 0;
    for (int i = bits.length - 1; i >= 0; i--) {
      if (bits[i] == 1) {
        result += pow(2, bits.length - 1 - i);
      }
    }
    return result;
  }

  /// 4 -> 00000100
  static List<int> to8Bit(int num) {
    String temp = num.toRadixString(2);
    List<int> result = [];
    temp.codeUnits.forEach((code) {
      result.add(code - 48);
    });
    int len = result.length;
    if (len < 8) {
      result.insertAll(0, List.generate(8, (index) => 0).sublist(len));
    }
    return result;
  }

  /// 4 -> 00000100
  static List<int> to4Bit(int num) {
    String temp = num.toRadixString(2);
    List<int> result = [];
    temp.codeUnits.forEach((code) {
      result.add(code - 48);
    });
    int len = result.length;
    if (len < 4) {
      result.insertAll(0, List.generate(4, (index) => 0).sublist(len));
    }
    return result;
  }
}
