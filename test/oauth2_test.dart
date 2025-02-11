import 'dart:async';

import 'package:dio/dio.dart';
import 'package:flutter_oauth2/flutter_oauth2.dart';
import 'package:mockito/annotations.dart';
import 'package:mockito/mockito.dart';
import "package:test/test.dart";

import 'oauth2_test.mocks.dart';

@GenerateMocks([Dio, TokenStorage])
void main() {
  const _ANY_ACCESS_TOKEN = "anyAccessToken";
  const _ANY_REFRESH_TOKEN = "anyRefreshToken";
  const _ANY_EXPIRES_IN = 123;
  const _ANOTHER_ACCESS_TOKEN = "anotherAccessToken";
  const _ANOTHER_REFRESH_TOKEN = "anotherRefreshToken";
  const _ANY_TOKEN_TYPE = AuthorizationTypeConst.BEARER;
  const _ANY_CONTENT_TYPE = "anyContentType";
  const _ANY_ERROR = "anyError";
  const _ANY_ERROR_DESCRIPTION = "anyErrorDescription";
  const _ANY_ERROR_CODE = 'anyErrorCode';
  const _ANY_ERROR_LIST = [
    {ResponseDataFieldConst.ERROR_CODE: _ANY_ERROR_CODE}
  ];

  late Dio _mockClient;
  late Credentials _anyCredentials;
  late Uri _anyAuthorizationEndpoint;
  late Headers _anyHeaders;
  late Uri _anyErrorUri;
  late TokenStorage _mockTokenStorage;

  setUp(() {
    _mockClient = MockDio();
    _anyCredentials = Credentials("any", "any");
    _anyAuthorizationEndpoint = Uri.https("mock.gcx", "/mockToken");
    _anyErrorUri = Uri.https("mock.gcx", "/mockError");
    _anyHeaders = Headers();
    _anyHeaders.add(HeaderTypeConst.CONTENT_TYPE, _ANY_CONTENT_TYPE);
    _mockTokenStorage = MockTokenStorage();
    when(_mockTokenStorage.clear()).thenAnswer((_) async => null);
    when(_mockTokenStorage.read()).thenAnswer((_) async => null);
    when(_mockTokenStorage.write(any)).thenAnswer((_) async => null);
  });

  group("Grant Type", () {
    test('"refresh_token" returns token if token is persistent', () async {
      // Assuming that a token storage is put into the config
      when(_mockTokenStorage.read()).thenAnswer((_) => Future.value(Token(
            _ANOTHER_ACCESS_TOKEN,
            _ANOTHER_REFRESH_TOKEN,
            DateTime.now().add(Duration(minutes: 10)),
          )));

      // And the authorization method is set to "refresh_token"
      var config = OAuthClientCredentialsConfig(
        authorizationEndpoint: _anyAuthorizationEndpoint,
        clientCredentials: _anyCredentials,
        httpClient: _mockClient,
        tokenStorage: _mockTokenStorage,
      );

      // If the OAuth2 authentication is called
      OAuth2 handler = OAuth2(config);
      var token = await handler.authenticate();

      // Expect the read method of the token storage to be called
      verify(_mockTokenStorage.read());

      // Expect the valid token to be returned
      expect(token?.accessToken, _ANOTHER_ACCESS_TOKEN);
      expect(token?.refreshToken, _ANOTHER_REFRESH_TOKEN);
      expect(token?.expiration, isNotNull);
    });

    test('"refresh_token" throws error if token is not persistent', () async {
      // Assuming that a token storage is put into the config
      // which does not include a token
      when(_mockTokenStorage.read()).thenAnswer(((_) async => null));

      // And the authorization method is set to "refresh_token"
      var config = OAuthRefreshTokenConfig(
        authorizationEndpoint: _anyAuthorizationEndpoint,
        clientCredentials: _anyCredentials,
        httpClient: _mockClient,
        tokenStorage: _mockTokenStorage,
      );

      // If the OAuth2 authentication is called
      OAuth2 handler = OAuth2(config);
      try {
        await handler.authenticate();
        fail('');
      } on StateError catch (_) {
        // Expect an exception to be thrown
      }
    });

    test('"client_credentials" returns token', () async {
      // Assuming that the client returns a valid token when calling
      // the authorization endpoint
      when(_mockClient.post(_anyAuthorizationEndpoint.toString(),
              data: anyNamed('data'), options: anyNamed('options')))
          .thenAnswer((_) => Future.value(Response(
              requestOptions: RequestOptions(path: ""),
              data: {
                ResponseDataFieldConst.ACCESS_TOKEN: _ANY_ACCESS_TOKEN,
                ResponseDataFieldConst.EXPIRES_IN: _ANY_EXPIRES_IN,
                ResponseDataFieldConst.TOKEN_TYPE: _ANY_TOKEN_TYPE
              },
              headers: _anyHeaders)));

      // And the authorization method is set to "client_credentials"
      var config = OAuthClientCredentialsConfig(
        authorizationEndpoint: _anyAuthorizationEndpoint,
        clientCredentials: _anyCredentials,
        httpClient: _mockClient,
      );

      // If the OAuth2 authentication is called
      OAuth2 handler = OAuth2(config);
      var token = await handler.authenticate();

      // Expect the client to be called once
      var verified = verify(_mockClient.post(
          _anyAuthorizationEndpoint.toString(),
          data: captureAnyNamed('data'),
          options: anyNamed('options')));
      verified.called(1);

      // Expect the request data to be correct
      expect(verified.captured.first, {
        RequestDataFieldConst.GRANT_TYPE: GrantTypeConst.CLIENT_CREDENTIALS
      });

      // Expect the valid token to be returned
      expect(token?.accessToken, _ANY_ACCESS_TOKEN);
      expect(token?.refreshToken, null);
      expect(token?.expiration, isNot(null));
    });

    test('"password" returns token', () async {
      // Assuming that the client returns a valid token when calling
      // the authorization endpoint
      when(_mockClient.post(_anyAuthorizationEndpoint.toString(),
              data: anyNamed('data'), options: anyNamed('options')))
          .thenAnswer((_) => Future.value(Response(
              requestOptions: RequestOptions(path: ""),
              data: {
                ResponseDataFieldConst.ACCESS_TOKEN: _ANY_ACCESS_TOKEN,
                ResponseDataFieldConst.REFRESH_TOKEN: _ANY_REFRESH_TOKEN,
                ResponseDataFieldConst.EXPIRES_IN: _ANY_EXPIRES_IN,
                ResponseDataFieldConst.TOKEN_TYPE: _ANY_TOKEN_TYPE
              },
              headers: _anyHeaders)));

      // And the authorization method is set to "password"
      var config = OAuthPasswordConfig(
        authorizationEndpoint: _anyAuthorizationEndpoint,
        clientCredentials: _anyCredentials,
        userCredentials: _anyCredentials,
        httpClient: _mockClient,
      );

      // If the OAuth2 authentication is called
      OAuth2 handler = OAuth2(config);
      var token = await handler.authenticate();

      // Expect the client to be called once
      var verified = verify(_mockClient.post(
          _anyAuthorizationEndpoint.toString(),
          data: captureAnyNamed('data'),
          options: anyNamed('options')));
      verified.called(1);

      // Expect the request data to be correct
      expect(verified.captured.first, {
        RequestDataFieldConst.GRANT_TYPE: GrantTypeConst.PASSWORD,
        RequestDataFieldConst.USERNAME: _anyCredentials.username,
        RequestDataFieldConst.PASSWORD: _anyCredentials.password
      });

      // Expect the valid token to be returned
      expect(token?.accessToken, _ANY_ACCESS_TOKEN);
      expect(token?.refreshToken, _ANY_REFRESH_TOKEN);
      expect(token?.expiration, isNotNull);
    });
  });

  group("Error response", () {
    test('with correct error format throws AuthorizationException', () async {
      // Assuming that the client returns an error when calling
      // the authorization endpoint
      when(_mockClient.post(_anyAuthorizationEndpoint.toString(),
              data: anyNamed('data'), options: anyNamed('options')))
          .thenThrow(
        DioError(
          requestOptions: RequestOptions(path: ""),
          response: Response(
            requestOptions: RequestOptions(path: ""),
            data: {
              ResponseDataFieldConst.ERROR: _ANY_ERROR,
              ResponseDataFieldConst.ERROR_DESCRIPTION: _ANY_ERROR_DESCRIPTION,
              ResponseDataFieldConst.ERROR_URI: _anyErrorUri.toString()
            },
          ),
        ),
      );

      var config = OAuthPasswordConfig(
        authorizationEndpoint: _anyAuthorizationEndpoint,
        clientCredentials: _anyCredentials,
        userCredentials: _anyCredentials,
        httpClient: _mockClient,
      );

      // If the OAuth2 authentication is called
      OAuth2 handler = OAuth2(config);
      try {
        // Expect the authentication to fail
        await handler.authenticate();
        fail("An AuthorizationException is expected here!");
      } on AuthorizationException catch (e) {
        // and to throw an exception with an error description
        expect(e.error, _ANY_ERROR);
        expect(e.description, _ANY_ERROR_DESCRIPTION);
        expect(e.uri, _anyErrorUri);
      }
    });

    test('with correct error list format throws AuthorizationException',
        () async {
      // Assuming that the client returns an error when calling
      // the authorization endpoint
      when(_mockClient.post(_anyAuthorizationEndpoint.toString(),
              data: anyNamed('data'), options: anyNamed('options')))
          .thenThrow(DioError(
              requestOptions: RequestOptions(path: ""),
              response: Response(
                requestOptions: RequestOptions(path: ""),
                data: {
                  ResponseDataFieldConst.ERROR_LIST: _ANY_ERROR_LIST,
                },
              )));

      var config = OAuthPasswordConfig(
        authorizationEndpoint: _anyAuthorizationEndpoint,
        clientCredentials: _anyCredentials,
        userCredentials: _anyCredentials,
        httpClient: _mockClient,
      );

      // If the OAuth2 authentication is called
      OAuth2 handler = OAuth2(config);
      try {
        // Expect the authentication to fail
        await handler.authenticate();
        fail("An AuthorizationException is expected here!");
      } on AuthorizationException catch (e) {
        // and to throw an exception with an error description
        expect(e.error, _ANY_ERROR_CODE);
        expect(e.description, null);
        expect(e.uri, null);
      }
    });

    test('without error included throws FormatException', () async {
      // Assuming that the client returns an invalid error when calling
      // the authorization endpoint
      when(_mockClient.post(_anyAuthorizationEndpoint.toString(),
              data: anyNamed('data'), options: anyNamed('options')))
          .thenThrow(
        DioError(
          requestOptions: RequestOptions(path: ""),
          response:
              Response(requestOptions: RequestOptions(path: ""), data: {}),
        ),
      );

      var config = OAuthPasswordConfig(
        authorizationEndpoint: _anyAuthorizationEndpoint,
        clientCredentials: _anyCredentials,
        userCredentials: _anyCredentials,
        httpClient: _mockClient,
      );

      // If the OAuth2 authentication is called
      OAuth2 handler = OAuth2(config);
      try {
        // Expect the authentication to fail
        await handler.authenticate();
        fail("An FormatException is expected here!");
      } on FormatException catch (e) {
        // and to throw an exception with the correct message
        expect(e.message,
            'did not contain required parameter "error" or "errors"');
      }
    });

    test('with wrong error type throws FormatException', () async {
      // Assuming that the client returns an invalid error when calling
      // the authorization endpoint
      when(_mockClient.post(_anyAuthorizationEndpoint.toString(),
              data: anyNamed('data'), options: anyNamed('options')))
          .thenThrow(DioError(
              requestOptions: RequestOptions(path: ""),
              response: Response(
                requestOptions: RequestOptions(path: ""),
                data: {
                  ResponseDataFieldConst.ERROR: ["wrong error type"]
                },
              )));

      var config = OAuthPasswordConfig(
        authorizationEndpoint: _anyAuthorizationEndpoint,
        clientCredentials: _anyCredentials,
        userCredentials: _anyCredentials,
        httpClient: _mockClient,
      );

      // If the OAuth2 authentication is called
      OAuth2 handler = OAuth2(config);
      try {
        // Expect the authentication to fail
        await handler.authenticate();
        fail("An FormatException is expected here!");
      } on FormatException catch (e) {
        // and to throw an exception with the correct message
        expect(
            e.message,
            contains(
                'required parameter "${ResponseDataFieldConst.ERROR}" was not a string, was'));
      }
    });

    test('with wrong error list type throws FormatException', () async {
      // Assuming that the client returns an invalid error when calling
      // the authorization endpoint
      when(_mockClient.post(_anyAuthorizationEndpoint.toString(),
              data: anyNamed('data'), options: anyNamed('options')))
          .thenThrow(DioError(
              requestOptions: RequestOptions(path: ""),
              response: Response(
                  requestOptions: RequestOptions(path: ""),
                  data: {
                    ResponseDataFieldConst.ERROR_LIST: "wrong error type"
                  })));

      var config = OAuthPasswordConfig(
        authorizationEndpoint: _anyAuthorizationEndpoint,
        clientCredentials: _anyCredentials,
        userCredentials: _anyCredentials,
        httpClient: _mockClient,
      );

      // If the OAuth2 authentication is called
      OAuth2 handler = OAuth2(config);
      try {
        // Expect the authentication to fail
        await handler.authenticate();
        fail("An FormatException is expected here!");
      } on FormatException catch (e) {
        // and to throw an exception with the correct message
        expect(
            e.message,
            contains(
                'required parameter "${ResponseDataFieldConst.ERROR_LIST}" was not a list, was'));
      }
    });

    test('with wrong error description type throws FormatException', () async {
      // Assuming that the client returns an invalid error when calling
      // the authorization endpoint
      when(_mockClient.post(_anyAuthorizationEndpoint.toString(),
              data: anyNamed('data'), options: anyNamed('options')))
          .thenThrow(DioError(
              requestOptions: RequestOptions(path: ""),
              response:
                  Response(requestOptions: RequestOptions(path: ""), data: {
                ResponseDataFieldConst.ERROR: _ANY_ERROR,
                ResponseDataFieldConst.ERROR_DESCRIPTION: [
                  "wrong error description"
                ],
                ResponseDataFieldConst.ERROR_URI: _anyErrorUri.toString()
              })));

      var config = OAuthPasswordConfig(
        authorizationEndpoint: _anyAuthorizationEndpoint,
        clientCredentials: _anyCredentials,
        userCredentials: _anyCredentials,
        httpClient: _mockClient,
      );

      // If the OAuth2 authentication is called
      OAuth2 handler = OAuth2(config);
      try {
        // Expect the authentication to fail
        await handler.authenticate();
        fail("An FormatException is expected here!");
      } on FormatException catch (e) {
        // and to throw an exception with the correct message
        expect(
            e.message,
            contains(
                'parameter "${ResponseDataFieldConst.ERROR_DESCRIPTION}" was not a string, was'));
      }
    });

    test('with wrong error uri type throws FormatException', () async {
      // Assuming that the client returns an invalid error when calling
      // the authorization endpoint
      when(_mockClient.post(_anyAuthorizationEndpoint.toString(),
              data: anyNamed('data'), options: anyNamed('options')))
          .thenThrow(DioError(
              requestOptions: RequestOptions(path: ""),
              response: Response(
                requestOptions: RequestOptions(path: ""),
                data: {
                  ResponseDataFieldConst.ERROR: _ANY_ERROR,
                  ResponseDataFieldConst.ERROR_DESCRIPTION:
                      _ANY_ERROR_DESCRIPTION,
                  ResponseDataFieldConst.ERROR_URI: ["wrong error URI"]
                },
              )));

      var config = OAuthPasswordConfig(
        authorizationEndpoint: _anyAuthorizationEndpoint,
        clientCredentials: _anyCredentials,
        userCredentials: _anyCredentials,
        httpClient: _mockClient,
      );

      // If the OAuth2 authentication is called
      OAuth2 handler = OAuth2(config);
      try {
        // Expect the authentication to fail
        await handler.authenticate();
        fail("An FormatException is expected here!");
      } on FormatException catch (e) {
        // and to throw an exception with the correct message
        expect(
            e.message,
            contains(
                'parameter "${ResponseDataFieldConst.ERROR_URI}" was not a string, was'));
      }
    });

    test('without response throws simple Exception', () async {
      // Assuming that the client returns an invalid error when calling
      // the authorization endpoint
      when(_mockClient.post(_anyAuthorizationEndpoint.toString(),
              data: anyNamed('data'), options: anyNamed('options')))
          .thenThrow(DioError(requestOptions: RequestOptions(path: "")));

      var config = OAuthPasswordConfig(
        authorizationEndpoint: _anyAuthorizationEndpoint,
        clientCredentials: _anyCredentials,
        userCredentials: _anyCredentials,
        httpClient: _mockClient,
      );

      // If the OAuth2 authentication is called
      OAuth2 handler = OAuth2(config);
      try {
        // Expect the authentication to fail
        await handler.authenticate();
        fail("An Exception is expected here!");
      } on Exception catch (_) {
        // and to throw an exception
      }
    });
  });

  group("Token response", () {
    test('with invalid format throws FormatException', () async {
      // Assuming that the client returns an invalid token when calling
      // the authorization endpoint
      when(_mockClient.post(_anyAuthorizationEndpoint.toString(),
              data: anyNamed('data'), options: anyNamed('options')))
          .thenAnswer((_) => Future.value(Response(
              requestOptions: RequestOptions(path: ""),
              data: {},
              headers: _anyHeaders)));

      var config = OAuthPasswordConfig(
        authorizationEndpoint: _anyAuthorizationEndpoint,
        clientCredentials: _anyCredentials,
        userCredentials: _anyCredentials,
        httpClient: _mockClient,
      );

      // If the OAuth2 authentication is called
      OAuth2 handler = OAuth2(config);
      try {
        // Expect the authentication to fail
        await handler.authenticate();
        fail("An FormatException is expected here!");
      } on FormatException catch (e) {
        // an to throw an exception
        expect(e.message, isNotNull);
      }
    });
  });

  group("Token storage", () {
    test('is cleared if reset flag is set', () async {
      // Assuming that the client returns a valid token when calling
      // the authorization endpoint
      when(_mockClient.post(_anyAuthorizationEndpoint.toString(),
              data: anyNamed('data'), options: anyNamed('options')))
          .thenAnswer((_) => Future.value(Response(
              requestOptions: RequestOptions(path: ""),
              data: {
                ResponseDataFieldConst.ACCESS_TOKEN: _ANY_ACCESS_TOKEN,
                ResponseDataFieldConst.EXPIRES_IN: _ANY_EXPIRES_IN,
                ResponseDataFieldConst.TOKEN_TYPE: _ANY_TOKEN_TYPE
              },
              headers: _anyHeaders)));

      // and a token storage is put into the config
      var config = OAuthClientCredentialsConfig(
        authorizationEndpoint: _anyAuthorizationEndpoint,
        clientCredentials: _anyCredentials,
        httpClient: _mockClient,
        tokenStorage: _mockTokenStorage,
      );

      // If the OAuth2 authentication is called with the reset flag
      OAuth2 handler = OAuth2(config);
      await handler.authenticate(reset: true);

      // Expect the clear method of the token storage to be called
      verify(_mockTokenStorage.clear());
    });

    test('is used to read token if no token is in memory', () async {
      // Assuming that a token storage is put into the config
      when(_mockTokenStorage.read()).thenAnswer((_) => Future.value(Token(
          _ANOTHER_ACCESS_TOKEN,
          _ANOTHER_REFRESH_TOKEN,
          DateTime.now().add(Duration(minutes: 10)))));

      var config = OAuthClientCredentialsConfig(
        authorizationEndpoint: _anyAuthorizationEndpoint,
        clientCredentials: _anyCredentials,
        httpClient: _mockClient,
        tokenStorage: _mockTokenStorage,
      );

      // If the OAuth2 authentication is called
      OAuth2 handler = OAuth2(config);
      var token = await handler.authenticate();

      // Expect the read method of the token storage to be called
      verify(_mockTokenStorage.read());

      // Expect the valid token to be returned
      expect(token?.accessToken, _ANOTHER_ACCESS_TOKEN);
      expect(token?.refreshToken, _ANOTHER_REFRESH_TOKEN);
      expect(token?.expiration, isNotNull);
    });

    test('is used to write token if new token is received', () async {
      // Assuming that the client returns a valid token when calling
      // the authorization endpoint
      when(_mockClient.post(_anyAuthorizationEndpoint.toString(),
              data: anyNamed('data'), options: anyNamed('options')))
          .thenAnswer((_) => Future.value(Response(
              requestOptions: RequestOptions(path: ""),
              data: {
                ResponseDataFieldConst.ACCESS_TOKEN: _ANY_ACCESS_TOKEN,
                ResponseDataFieldConst.EXPIRES_IN: _ANY_EXPIRES_IN,
                ResponseDataFieldConst.TOKEN_TYPE: _ANY_TOKEN_TYPE
              },
              headers: _anyHeaders)));

      // and a token storage is put into the config
      var config = OAuthClientCredentialsConfig(
        authorizationEndpoint: _anyAuthorizationEndpoint,
        clientCredentials: _anyCredentials,
        httpClient: _mockClient,
        tokenStorage: _mockTokenStorage,
      );

      // If the OAuth2 authentication is called
      OAuth2 handler = OAuth2(config);
      await handler.authenticate();

      // Expect the write method of the token storage to be called
      // after a new token is received
      verify(_mockTokenStorage.write(argThat(isNotNull)));
    });

    test('is allowed to return empty value', () async {
      // Assuming that the client returns a valid token when calling
      // the authorization endpoint
      when(_mockClient.post(_anyAuthorizationEndpoint.toString(),
              data: anyNamed('data'), options: anyNamed('options')))
          .thenAnswer((_) => Future.value(Response(
              requestOptions: RequestOptions(path: ""),
              data: {
                ResponseDataFieldConst.ACCESS_TOKEN: _ANY_ACCESS_TOKEN,
                ResponseDataFieldConst.REFRESH_TOKEN: _ANY_REFRESH_TOKEN,
                ResponseDataFieldConst.EXPIRES_IN: _ANY_EXPIRES_IN,
                ResponseDataFieldConst.TOKEN_TYPE: _ANY_TOKEN_TYPE
              },
              headers: _anyHeaders)));

      // and a token storage is put into the config
      var config = OAuthClientCredentialsConfig(
        authorizationEndpoint: _anyAuthorizationEndpoint,
        clientCredentials: _anyCredentials,
        httpClient: _mockClient,
        tokenStorage: _mockTokenStorage,
      );

      // If the OAuth2 authentication is called
      OAuth2 handler = OAuth2(config);
      var token = await handler.authenticate();

      // Expect the read method of the token storage to be called
      verify(_mockTokenStorage.read());

      // Expect the valid token to be returned
      expect(token?.accessToken, _ANY_ACCESS_TOKEN);
      expect(token?.refreshToken, _ANY_REFRESH_TOKEN);
      expect(token?.expiration, isNotNull);
    });
  });

  group("Expiration", () {
    test('If token is expired then refresh token', () async {
      // Assuming that the client returns a valid token when calling
      // the authorization endpoint
      when(_mockClient.post(_anyAuthorizationEndpoint.toString(),
              data: anyNamed('data'), options: anyNamed('options')))
          .thenAnswer((_) => Future.value(Response(
              requestOptions: RequestOptions(path: ""),
              data: {
                ResponseDataFieldConst.ACCESS_TOKEN: _ANY_ACCESS_TOKEN,
                ResponseDataFieldConst.REFRESH_TOKEN: _ANY_REFRESH_TOKEN,
                ResponseDataFieldConst.EXPIRES_IN: _ANY_EXPIRES_IN,
                ResponseDataFieldConst.TOKEN_TYPE: _ANY_TOKEN_TYPE
              },
              headers: _anyHeaders)));

      // Assuming that a token storage is put into the config
      // which returns an expired token
      when(_mockTokenStorage.read()).thenAnswer((_) => Future.value(Token(
          _ANOTHER_ACCESS_TOKEN,
          _ANOTHER_REFRESH_TOKEN,
          DateTime.now().subtract(Duration(minutes: 10)))));
      var config = OAuthClientCredentialsConfig(
        authorizationEndpoint: _anyAuthorizationEndpoint,
        clientCredentials: _anyCredentials,
        httpClient: _mockClient,
        tokenStorage: _mockTokenStorage,
      );

      // If the OAuth2 authentication is called
      OAuth2 handler = OAuth2(config);
      var token = await handler.authenticate();

      // Expect the client to be called once
      var verified = verify(_mockClient.post(
          _anyAuthorizationEndpoint.toString(),
          data: captureAnyNamed('data'),
          options: anyNamed('options')));
      verified.called(1);

      // Expect the request data to be correct
      var data = verified.captured;
      expect(data.first, {
        RequestDataFieldConst.GRANT_TYPE: GrantTypeConst.REFRESH_TOKEN,
        RequestDataFieldConst.REFRESH_TOKEN: _ANOTHER_REFRESH_TOKEN
      });

      // Expect the valid token to be returned
      expect(token?.accessToken, _ANY_ACCESS_TOKEN);
      expect(token?.refreshToken, _ANY_REFRESH_TOKEN);
      expect(token?.expiration, isNotNull);
    });

    test(
        'If token is expired and no refresh token is available get new token by credentials',
        () async {
      // Assuming that the client returns a valid token when calling
      // the authorization endpoint
      when(_mockClient.post(_anyAuthorizationEndpoint.toString(),
              data: anyNamed('data'), options: anyNamed('options')))
          .thenAnswer((_) => Future.value(Response(
              requestOptions: RequestOptions(path: ""),
              data: {
                ResponseDataFieldConst.ACCESS_TOKEN: _ANY_ACCESS_TOKEN,
                ResponseDataFieldConst.REFRESH_TOKEN: _ANY_REFRESH_TOKEN,
                ResponseDataFieldConst.EXPIRES_IN: _ANY_EXPIRES_IN,
                ResponseDataFieldConst.TOKEN_TYPE: _ANY_TOKEN_TYPE
              },
              headers: _anyHeaders)));

      // Assuming that a token storage is put into the config
      // which returns an expired token without refresh token
      when(_mockTokenStorage.read()).thenAnswer((_) => Future.value(Token(
          _ANOTHER_ACCESS_TOKEN,
          null, // no refresh token
          DateTime.now().subtract(Duration(minutes: 10)))));

      var config = OAuthClientCredentialsConfig(
        authorizationEndpoint: _anyAuthorizationEndpoint,
        clientCredentials: _anyCredentials,
        httpClient: _mockClient,
        tokenStorage: _mockTokenStorage,
      );

      // If the OAuth2 authentication is called
      OAuth2 handler = OAuth2(config);
      var token = await handler.authenticate();

      // Expect the client to be called once
      var verified = verify(_mockClient.post(
          _anyAuthorizationEndpoint.toString(),
          data: captureAnyNamed('data'),
          options: anyNamed('options')));
      verified.called(1);

      // Expect the request data to be correct
      expect(verified.captured.first, {
        RequestDataFieldConst.GRANT_TYPE: GrantTypeConst.CLIENT_CREDENTIALS
      });

      // Expect the valid token to be returned
      expect(token?.accessToken, _ANY_ACCESS_TOKEN);
      expect(token?.refreshToken, _ANY_REFRESH_TOKEN);
      expect(token?.expiration, isNotNull);
    });
  });
}
