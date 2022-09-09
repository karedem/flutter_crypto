///
/// 3des_RealityEnvronmentTest
/// 生产环境代码测试

import 'dart:convert';
import 'package:dartcrypto/des/des.dart';
import 'package:test/test.dart';

/// 加密des pkcks7padding cbc key+iv
///
/// [msg]是utf-16待加密消息体,[key]是加密key.
String encryptDes2Base64(String msg, String key) {
  // 把UTF16处理为UTF8字节序列 中文转换
  final enc = Utf8Encoder().convert(msg).toList();
  // 常规字节加密
  var ciphertext = DES().encryptWithCBC(enc, key.codeUnits, iv: key);
  var b64 = Base64Encoder().convert(ciphertext);
  return b64;
}

/// 从base64秘文中解密
///
/// List<int> 可以理解为ByteArray或者字节集 不等同于Uint8List 有符号int8 没有array的概念。
/// 由于Dart中的字符串是UTF16的类型，所以`Utf8Encoder().convert(key).toList()`转为UTF8序列。
/// 而8正是16的父集 可以兼容8 所以可以不转换也可以使用[String.codeUnits]获得数据.
/// 但是中文不行！！必须转UTF8 Uint8List !== List<int>
///
/// [msg]是base64加密后的数据,[key]就是常规的utf-8key即可。如果有8位iv可以直接写
String decryptDES4Base64(String msg, String key) {
  final msg1 = Base64Decoder().convert(msg);
  final bits = DES().decryptWithCBC(msg1, key.codeUnits, iv: key);
  return String.fromCharCodes(bits);
}

/// 测试用加密后数据
/// 数据分两段 用%分割 前一段的前8字节加密后一段加密数据 详细算法看 [生成测试test]
const fakeResponse =
    '0IIDcu+kXd0B2eFFhe9ZBrdIgfBXxtI1iiSKwytUVPHRPMndIfwWTpGSHpW1dE3nBctx/xkoxIo4Wr4Y5GZN4Cp0nNxNBK6dTpOtR6uXmlqQoFjhu+VfqYzqcQYIuxE2sCBAkUDEfWeGx3E+s9h+GQ==%5wv3150Jbkss7R1Xus6PUg==';

late final String qq;
late final String skey;
late final String fakerEncryptInfo;

void main() {
  test("生成测试已加密数据", () {
    var _qq = '123456789';
    final willEnc =
        ';uin=o$_qq; skey=asdasdasdf; p_uin=o$_qq; p_skey=asdas%^&dfaA!@#*aYasdasd;';

    if (_qq.length < 8) _qq += "QMD";
    final encInfo = encryptDes2Base64(willEnc, _qq.substring(0, 8));
    print(encInfo);
    final encHead = encryptDes2Base64(_qq, encInfo.substring(0, 8));
    print(encHead);
    if (encInfo.isEmpty || encHead.isEmpty) throw Exception("出错啦！加密失败。");
    fakerEncryptInfo = '$encInfo%$encHead';
  });

  test("测试3DES数据解密", () {
    final replace = fakerEncryptInfo.replaceAll("-", "").replaceAll("|", "");
    if (replace.length < 10 || replace.matchAsPrefix("%") == -1) return null;
    final split = replace.split("%");
    var key = split[0];

    qq = decryptDES4Base64(split[1], key.substring(0, 8));

    if (qq.length < 8) qq += "QMD";
    skey = decryptDES4Base64(key, qq.substring(0, 8));
    print("decode: qq is [$qq],skey is [$skey]");
    if (qq.isEmpty || skey.isEmpty) throw Exception("解密出现不可饶恕的错误");
  });

  test("3DES加密 支持中文状况", () {
    var uid = "822a3b85-a5c9-438e-a277-a8da412e8265",
        systemVersion = "1.7.2",
        versionCode = "76",
        deviceBrand = "360奇虎", //测试3DES中文加密
        deviceModel = "QK1707-A01",
        appVersion = "7.1.2",
        encIP = encryptDes2Base64(
            '$uid$deviceModel$deviceBrand$systemVersion$appVersion$versionCode',
            "QMDF*ckYou!".substring(0, 8));
    print("EncIP is $encIP");
    if (encIP.length <= 0) throw Exception("3DES加密出现错误");
  });
}
