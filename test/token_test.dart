import 'package:dio/dio.dart';
import 'package:flutter_oauth2/flutter_oauth2.dart';
import 'package:test/test.dart';

void main() {
  const _ANY_ACCESS_TOKEN = "anyAccessToken";
  const _ANY_REFRESH_TOKEN = "anyRefreshToken";
  const _ANY_EXPIRES_IN = 123;
  const _ANY_TOKEN_TYPE = AuthorizationTypeConst.BEARER;
  const _ANY_CONTENT_TYPE = "anyContentType";

  late Headers _anyHeaders;

  setUp(() {
    _anyHeaders = Headers();
    _anyHeaders.add(HeaderTypeConst.CONTENT_TYPE, _ANY_CONTENT_TYPE);
  });

  group("Expiration", () {
    test('is expired if empty', () {
      var token = Token(_ANY_ACCESS_TOKEN, _ANY_REFRESH_TOKEN, null);

      // Expect the token to be expired
      expect(token.isExpired, true);
    });

    test('is expired if date is in the past', () {
      var token = Token(_ANY_ACCESS_TOKEN, _ANY_REFRESH_TOKEN,
          DateTime.now().subtract(Duration(minutes: 10)));

      // Expect the token to be expired
      expect(token.isExpired, true);
    });

    test('is valid if date is in the future', () {
      var token = Token(_ANY_ACCESS_TOKEN, _ANY_REFRESH_TOKEN,
          DateTime.now().add(Duration(minutes: 10)));

      // Expect the token to be valid
      expect(token.isExpired, false);
    });
  });

  group("From Response Factory", () {
    test('returns token if response is valid', () {
      var response = Response(
          requestOptions: RequestOptions(path: ""),
          data: {
            ResponseDataFieldConst.ACCESS_TOKEN: _ANY_ACCESS_TOKEN,
            ResponseDataFieldConst.REFRESH_TOKEN: _ANY_REFRESH_TOKEN,
            ResponseDataFieldConst.EXPIRES_IN: _ANY_EXPIRES_IN,
            ResponseDataFieldConst.TOKEN_TYPE: _ANY_TOKEN_TYPE
          },
          headers: _anyHeaders);

      var token = Token.fromResponse(response, DateTime.now());

      // Expect the valid token to be returned
      expect(token.accessToken, _ANY_ACCESS_TOKEN);
      expect(token.refreshToken, _ANY_REFRESH_TOKEN);
      expect(token.expiration, isNotNull);
    });

    test('returns token if response does not include a refresh token', () {
      var response = Response(
          requestOptions: RequestOptions(path: ""),
          data: {
            ResponseDataFieldConst.ACCESS_TOKEN: _ANY_ACCESS_TOKEN,
            // no refresh token
            ResponseDataFieldConst.EXPIRES_IN: _ANY_EXPIRES_IN,
            ResponseDataFieldConst.TOKEN_TYPE: _ANY_TOKEN_TYPE
          },
          headers: _anyHeaders);

      var token = Token.fromResponse(response, DateTime.now());

      // Expect the valid token to be returned
      expect(token.accessToken, _ANY_ACCESS_TOKEN);
      expect(token.refreshToken, null);
      expect(token.expiration, isNotNull);
    });

    test('returns token if response does not include "expires_in"', () {
      var response = Response(
          requestOptions: RequestOptions(path: ""),
          data: {
            ResponseDataFieldConst.ACCESS_TOKEN: _ANY_ACCESS_TOKEN,
            ResponseDataFieldConst.REFRESH_TOKEN: _ANY_REFRESH_TOKEN,
            ResponseDataFieldConst.TOKEN_TYPE: _ANY_TOKEN_TYPE
          },
          headers: _anyHeaders);

      var token = Token.fromResponse(response, DateTime.now());

      // Expect the valid token to be returned
      expect(token.accessToken, _ANY_ACCESS_TOKEN);
      expect(token.refreshToken, _ANY_REFRESH_TOKEN);
      expect(token.expiration, null);
    });

    test('returns token with empty expiration if no start time is given', () {
      var response = Response(
          requestOptions: RequestOptions(path: ""),
          data: {
            ResponseDataFieldConst.ACCESS_TOKEN: _ANY_ACCESS_TOKEN,
            ResponseDataFieldConst.REFRESH_TOKEN: _ANY_REFRESH_TOKEN,
            ResponseDataFieldConst.EXPIRES_IN: _ANY_EXPIRES_IN,
            ResponseDataFieldConst.TOKEN_TYPE: _ANY_TOKEN_TYPE
          },
          headers: _anyHeaders);

      var token = Token.fromResponse(response, null);

      // Expect the valid token to be returned
      expect(token.accessToken, _ANY_ACCESS_TOKEN);
      expect(token.refreshToken, _ANY_REFRESH_TOKEN);
      expect(token.expiration, null);
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
      var response = Response(
          requestOptions: RequestOptions(path: ""),
          data: ["not a map"],
          headers: _anyHeaders);

      try {
        Token.fromResponse(response, DateTime.now());
        fail("An FormatException is expected here!");
      } on FormatException catch (e) {
        expect(e.message, contains('Response data cannot be read.'));
      }
    });

    test('throws FormatException if content type is missing', () {
      var response = Response(
          requestOptions: RequestOptions(path: ""),
          data: {
            ResponseDataFieldConst.ACCESS_TOKEN: _ANY_ACCESS_TOKEN,
            ResponseDataFieldConst.REFRESH_TOKEN: _ANY_REFRESH_TOKEN,
            ResponseDataFieldConst.EXPIRES_IN: _ANY_EXPIRES_IN,
            ResponseDataFieldConst.TOKEN_TYPE: _ANY_TOKEN_TYPE
          },
          headers: Headers());

      try {
        Token.fromResponse(response, DateTime.now());
        fail("An FormatException is expected here!");
      } on FormatException catch (e) {
        expect(e.message, contains('Missing Content-Type string.'));
      }
    });

    test('throws FormatException if access token is missing', () {
      var response = Response(
          requestOptions: RequestOptions(path: ""),
          data: {
            // no access token
            ResponseDataFieldConst.REFRESH_TOKEN: _ANY_REFRESH_TOKEN,
            ResponseDataFieldConst.EXPIRES_IN: _ANY_EXPIRES_IN,
            ResponseDataFieldConst.TOKEN_TYPE: _ANY_TOKEN_TYPE
          },
          headers: _anyHeaders);

      try {
        Token.fromResponse(response, DateTime.now());
        fail("An FormatException is expected here!");
      } on FormatException catch (e) {
        expect(
            e.message,
            contains(
                'did not contain required parameter "${ResponseDataFieldConst.ACCESS_TOKEN}"'));
      }
    });

    test('throws FormatException if token type is missing', () {
      var response = Response(
          requestOptions: RequestOptions(path: ""),
          data: {
            ResponseDataFieldConst.ACCESS_TOKEN: _ANY_ACCESS_TOKEN,
            ResponseDataFieldConst.REFRESH_TOKEN: _ANY_REFRESH_TOKEN,
            ResponseDataFieldConst.EXPIRES_IN: _ANY_EXPIRES_IN
            // no token type
          },
          headers: _anyHeaders);

      try {
        Token.fromResponse(response, DateTime.now());
        fail("An FormatException is expected here!");
      } on FormatException catch (e) {
        expect(
            e.message,
            contains(
                'did not contain required parameter "${ResponseDataFieldConst.TOKEN_TYPE}"'));
      }
    });

    test('throws FormatException if token type is incorrect', () {
      var response = Response(
          requestOptions: RequestOptions(path: ""),
          data: {
            ResponseDataFieldConst.ACCESS_TOKEN: _ANY_ACCESS_TOKEN,
            ResponseDataFieldConst.REFRESH_TOKEN: _ANY_REFRESH_TOKEN,
            ResponseDataFieldConst.EXPIRES_IN: _ANY_EXPIRES_IN,
            ResponseDataFieldConst.TOKEN_TYPE: "wrong token type"
            // no token type
          },
          headers: _anyHeaders);

      try {
        Token.fromResponse(response, DateTime.now());
        fail("An FormatException is expected here!");
      } on FormatException catch (e) {
        expect(e.message, contains('Unknown token type'));
      }
    });

    test('throws FormatException if "expires in" is not an integer', () {
      var response = Response(
          requestOptions: RequestOptions(path: ""),
          data: {
            ResponseDataFieldConst.ACCESS_TOKEN: _ANY_ACCESS_TOKEN,
            ResponseDataFieldConst.REFRESH_TOKEN: _ANY_REFRESH_TOKEN,
            ResponseDataFieldConst.EXPIRES_IN: "not an integer",
            ResponseDataFieldConst.TOKEN_TYPE: _ANY_TOKEN_TYPE
            // no token type
          },
          headers: _anyHeaders);

      try {
        Token.fromResponse(response, DateTime.now());
        fail("An FormatException is expected here!");
      } on FormatException catch (e) {
        expect(
            e.message,
            contains(
                'parameter "${ResponseDataFieldConst.EXPIRES_IN}" was not an int, was'));
      }
    });

    test('throws FormatException if refresh token is not a string', () {
      var response = Response(
          requestOptions: RequestOptions(path: ""),
          data: {
            ResponseDataFieldConst.ACCESS_TOKEN: _ANY_ACCESS_TOKEN,
            ResponseDataFieldConst.REFRESH_TOKEN: ["not a string"],
            ResponseDataFieldConst.EXPIRES_IN: _ANY_EXPIRES_IN,
            ResponseDataFieldConst.TOKEN_TYPE: _ANY_TOKEN_TYPE
            // no token type
          },
          headers: _anyHeaders);

      try {
        Token.fromResponse(response, DateTime.now());
        fail("An FormatException is expected here!");
      } on FormatException catch (e) {
        expect(
            e.message,
            contains(
                'parameter "${ResponseDataFieldConst.REFRESH_TOKEN}" was not a string, was'));
      }
    });
  });

  group('JSON Serialization', () {
    test('returns all Token properties in Json', () {
      var expiration = DateTime.now();
      var token = Token(_ANY_ACCESS_TOKEN, _ANY_REFRESH_TOKEN, expiration);

      var json = token.toJson();

      expect(
          json,
          equals({
            TokenSerializationConst.ACCESS_TOKEN: _ANY_ACCESS_TOKEN,
            TokenSerializationConst.REFRESH_TOKEN: _ANY_REFRESH_TOKEN,
            TokenSerializationConst.EXPIRATION: expiration.toIso8601String(),
          }));
    });

    test('returns valid Token from Json', () {
      var json = {
        TokenSerializationConst.ACCESS_TOKEN: _ANY_ACCESS_TOKEN,
        TokenSerializationConst.REFRESH_TOKEN: _ANY_REFRESH_TOKEN,
      };

      var token = Token.fromJson(json);

      expect(token.accessToken, _ANY_ACCESS_TOKEN);
      expect(token.refreshToken, _ANY_REFRESH_TOKEN);
      expect(token.expiration, null);
    });
  });
}
