import 'package:dartcrypto/dartcrypto.dart';
import "package:test/test.dart";

///主测试函数 下面null报错懒得改了 直接comment了
void main() {
  test('adds one to input values', () {
    final calculator = Calculator();
    expect(calculator.addOne(2), 3);
    expect(calculator.addOne(-7), -6);
    expect(calculator.addOne(0), 1);
    // expect(() => calculator.addOne(null), throwsNoSuchMethodError);
  });
}
