class NumberUtils {
  ///二进制数组转字节数组
  static List<int> intListFromBits(List<int> bits) {
    //print("${bits.toString()} ${bits.length ~/ 8}");
    List<int> result = List.generate(bits.length >> 3, (index) => 0);
    for (int i = 0; i < bits.length; i++) {
      result[i >> 3] |= (bits[i] << (7 - i & 7));
    }
    return result;
  }

  ///字节数组转二进制数组
  static List<int> bitsFromIntList(List<int> ints) {
    List<int> result = List.filled(ints.length << 3, 0);
    for (int i = 0; i < (ints.length << 3); ++i) {
      result[i] = (ints[i >> 3] >> (7 - i & 7)) & 1;
    }
    return result;
//    List<int> result = [];
//    ints.forEach((i) {
//      result.addAll(to8Bit(i));
//    });
//    return result;
  }

  ///二进制字符串转数字
  static int intFromBits(List<int> bits) {
    //return int.parse(bits.join(), radix: 2);
    int result = 0;
    for (int i = 0; i < bits.length; i++) {
      result |= (bits[i] << (7 - i & 7));
    }
    return result;
  }

  ///to8Bit  01100100
  static List<int> t8Bit(List<int> bytes) {
    List<int> result = List.filled(8 * bytes.length, 0);
    for (int i = 0; i < 8 * bytes.length; ++i) {
      result[i] = (bytes[i >> 3] >> (7 - i & 7)) & 1;
    }
    return result;
  }

  /// 4 -> 00000100
  static List<int> to8Bit(int num) {
    List<int> result = List.filled(8, 0);
    for (int i = 0; i < 8; i++) {
      result[i] = (num >> (7 - i & 7)) & 1;
    }
    return result;
  }

  /// 4 -> 0100
  static List<int> to4Bit(int num) {
    List<int> result = List.filled(4, 0);
    for (int i = 0; i < 4; i++) {
      result[i] = (num >> (3 - i & 3)) & 1;
    }
    return result;
  }

  static String formatSeeds(int seeds) {
    if (seeds > 9999) {
      return '${(seeds / 10000.0).toStringAsFixed(1)}w';
    } else if (seeds > 999) {
      return '${(seeds / 1000.0).toStringAsFixed(1)}k';
    } else {
      return '$seeds';
    }
  }
}
