import 'dart:typed_data';

class CryptoUtil {
  static List<int> hex2List(String hexStr) {
    if (hexStr == null || hexStr.length % 2 != 0) {
      //十六进制字符串错误
      return null;
    }

    if (hexStr.startsWith('0x')) {
      hexStr = hexStr.substring(2);
    }
    List<int> result = List(hexStr.length ~/ 2);
    String temp = '0123456789ABCDEF';
    for (int i = 0; i < hexStr.length; i += 2) {
      int h = temp.indexOf(hexStr.substring(i, i + 1));
      int l = temp.indexOf(hexStr.substring(i + 1, i + 2));
      result[i ~/ 2] = (h * 16 + l);
    }
    return result;
  }

  static String list2Hex(List<int> list) {
    List<String> results = List(list.length * 2);
    String temp = '0123456789ABCDEF';
    for (int i = 0; i < list.length; i++) {
      int h = list[i] ~/ 16;
      int l = list[i] % 16;
      results[i * 2] = temp.substring(h, h + 1);
      results[i * 2 + 1] = temp.substring(l, l + 1);
    }
    return results.join();
  }
}
