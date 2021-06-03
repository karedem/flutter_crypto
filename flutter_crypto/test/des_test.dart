// This is a basic Flutter widget test.
//
// To perform an interaction with a widget in your test, use the WidgetTester
// utility that Flutter provides. For example, you can send tap and scroll
// gestures. You can also use WidgetTester to find child widgets in the widget
// tree, read text, and verify that the values of widget properties are correct.

import 'package:flutter_test/flutter_test.dart';
import 'package:fluttercrypto/des/des.dart';
import 'package:fluttercrypto/util/crypto_util.dart';
import 'package:fluttercrypto/util/number_utils.dart';

void main() {
  test('hex test', () {
    List<int> list = CryptoUtil.hex2List('0123456789ABCDEF');
    print(list.toString());
    list.forEach((i) {
      print(NumberUtils.to8Bit(i).toString());
      print(NumberUtils.intFromBits(NumberUtils.to8Bit(i)));
    });

    //print([1, 2, 3, 4, 5, 6].sublist(0, 4).toString());
  });

  test('des ecb test', () async {
    //
    String hexKey = '133457799BBCDFF1';
    String data = '0123456789ABCDEF';

    String cipher = DES().encryptToHexWithECB(data, hexKey);
    print('cipher $cipher');
    String plain = DES().decryptFromHexWithECB(cipher, hexKey);
    print('plain ' + plain.toString());

    ///多数在线加密网站的key使用的是utf-8格式 这里是十六进制格式
    String testKey = 'asfd1234';
    print('网站测试key: $testKey');
    print('对应十六进制key: ${CryptoUtil.list2Hex(testKey.codeUnits)}');
    print(
        '对应 cipher: ${DES().encryptToHexWithECB(data, CryptoUtil.list2Hex(testKey.codeUnits))}');
  });

  test('des cbc test', () async {
    //

    String hexKey = '133457799BBCDFF1';
    String data = 'asdasdasd啊啊啊';
    String cipher = DES().encryptToHexWithCBC(data, hexKey);
    print('cipher ' + cipher);
    String plain = DES().decryptFromHexWithCBC(cipher, hexKey);
    print('plain ' + plain);
  });

  test('bit test', () async {
    List<int> bits = NumberUtils.to8Bit(100);
    int number = NumberUtils.intFromBits(bits);
    print(NumberUtils.to4Bit(2));
    print(bits.toString());
    print(number.toString());
  });

  test('e_transform test', () {
    List<int> l1 = NumberUtils.bitsFromIntList(CryptoUtil.hex2List('10A10001'));
    print(l1);
    List<int> p = DES().E_transform(l1);
    print(p);
    List<int> l2 = NumberUtils.intListFromBits(p);
    print(CryptoUtil.list2Hex(l2));
  });

  test('p_transform test', () {
    List<int> l1 = NumberUtils.bitsFromIntList(CryptoUtil.hex2List('10A10001'));
    print(l1);
    List<int> p = DES().P_transform(l1);
    print(p);
    List<int> l2 = NumberUtils.intListFromBits(p);
    print(CryptoUtil.list2Hex(l2));
  });
}
