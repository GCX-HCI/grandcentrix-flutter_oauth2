import 'package:dio/dio.dart';
import 'package:flutter_oauth2/helper/const.dart';
import 'package:flutter_oauth2/token/token.dart';
import 'package:test/test.dart';

void main() {
  const _ANY_ACCESS_TOKEN = "anyAccessToken";
  const _ANY_REFRESH_TOKEN = "anyRefreshToken";
  const _ANY_EXPIRES_IN = 123;
  const _ANY_TOKEN_TYPE = AuthorizationTypeConst.BEARER;
  const _ANY_CONTENT_TYPE = "anyContentType";

  Headers _anyHeaders;

  setUp(() {
    _anyHeaders = Headers();
    _anyHeaders.add(HeaderTypeConst.CONTENT_TYPE, _ANY_CONTENT_TYPE);
  });

  group("Factory", () {
    test('returns token if response is valid', () {
      var response = Response(data: {
        ResponseDataFieldConst.ACCESS_TOKEN: _ANY_ACCESS_TOKEN,
        ResponseDataFieldConst.REFRESH_TOKEN: _ANY_REFRESH_TOKEN,
        ResponseDataFieldConst.EXPIRES_IN: _ANY_EXPIRES_IN,
        ResponseDataFieldConst.TOKEN_TYPE: _ANY_TOKEN_TYPE
      }, headers: _anyHeaders);

      var token = Token.fromResponse(response, DateTime.now());

      // Expect the valid token to be returned
      expect(token.accessToken, _ANY_ACCESS_TOKEN);
      expect(token.refreshToken, _ANY_REFRESH_TOKEN);
      expect(token.expiration, isNotNull);
    });

    test('throws FormatException if response is null', () {
      try {
        Token.fromResponse(null, DateTime.now());
        fail("An FormatException is expected here!");
      } on FormatException catch (e) {
        expect(e.message, contains('Response data cannot be read.'));
      }
    });

    test('throws FormatException if response data is not a map', () {
      var response = Response(data: ["not a map"], headers: _anyHeaders);

      try {
        Token.fromResponse(response, DateTime.now());
        fail("An FormatException is expected here!");
      } on FormatException catch (e) {
        expect(e.message, contains('Response data cannot be read.'));
      }
    });

    test('throws FormatException if content type is missing', () {
      var response = Response(data: {
        ResponseDataFieldConst.ACCESS_TOKEN: _ANY_ACCESS_TOKEN,
        ResponseDataFieldConst.REFRESH_TOKEN: _ANY_REFRESH_TOKEN,
        ResponseDataFieldConst.EXPIRES_IN: _ANY_EXPIRES_IN,
        ResponseDataFieldConst.TOKEN_TYPE: _ANY_TOKEN_TYPE
      }, headers: Headers());

      try {
        Token.fromResponse(response, DateTime.now());
        fail("An FormatException is expected here!");
      } on FormatException catch (e) {
        expect(e.message, contains('Missing Content-Type string.'));
      }
    });
  });
}
