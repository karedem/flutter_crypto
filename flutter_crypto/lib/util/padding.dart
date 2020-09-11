class Padding {
  static List<int> pkcs7Padding(List<int> data) {
    List<int> padDate = [];
    int fillLen = 8 - data.length % 8;
    padDate.addAll(data);
    for (int i = 0; i < fillLen; i++) {
      padDate.add(fillLen);
    }
    return padDate;
  }

  static List<int> pkcs7UnPadding(List<int> padData) {
    int fillLen = padData.last;
    if (fillLen < 0 || fillLen > 8) {
      return padData;
    }
    List<int> data = padData.sublist(0, padData.length - fillLen);
    return data;
  }
}
