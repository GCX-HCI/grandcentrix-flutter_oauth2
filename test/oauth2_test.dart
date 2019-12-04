import 'package:dio/dio.dart';
import 'package:flutter_oauth2/helper/const.dart';
import 'package:flutter_oauth2/helper/exception.dart';
import 'package:flutter_oauth2/oauth2.dart';
import 'package:flutter_oauth2/token/token.dart';
import 'package:mockito/mockito.dart';
import "package:test/test.dart";

class MockClient extends Mock implements Dio {}

class MockTokenStorage extends Mock implements TokenStorage {}

void main() {
  const _ANY_ACCESS_TOKEN = "anyAccessToken";
  const _ANY_REFRESH_TOKEN = "anyRefreshToken";
  const _ANY_EXPIRES_IN = 123;
  const _ANOTHER_ACCESS_TOKEN = "anotherAccessToken";
  const _ANOTHER_REFRESH_TOKEN = "anotherRefreshToken";
  const _ANY_TOKEN_TYPE = AuthorizationType.BEARER;
  const _ANY_CONTENT_TYPE = "anyContentType";
  const _ANY_ERROR = "anyError";
  const _ANY_ERROR_DESCRIPTION = "anyErrorDescription";

  Dio _mockClient = MockClient();
  Credentials _anyCredentials = Credentials("any", "any");
  Uri _anyAuthorizationEndpoint = Uri.https("mock.gcx", "/mockToken");
  Headers _anyHeaders = Headers();
  Uri _anyErrorUri = Uri.https("mock.gcx", "/mockError");

  setUp(() {
    _anyHeaders.add(HeaderType.CONTENT_TYPE, _ANY_CONTENT_TYPE);
  });

  group("Grant Type", () {
    test('"client_credentials" returns token', () async {
      // Assuming that the client returns a valid token when calling
      // the authorization endpoint
      when(_mockClient.post(_anyAuthorizationEndpoint.toString(),
              data: anyNamed('data'), options: anyNamed('options')))
          .thenAnswer((_) => Future.value(Response(data: {
                ResponseDataField.ACCESS_TOKEN: _ANY_ACCESS_TOKEN,
                ResponseDataField.EXPIRES_IN: _ANY_EXPIRES_IN,
                ResponseDataField.TOKEN_TYPE: _ANY_TOKEN_TYPE
              }, headers: _anyHeaders)));

      // And the authorization method is set to "client_credentials"
      var config = Config(
          authorizationEndpoint: _anyAuthorizationEndpoint,
          grantType: GrantType.CLIENT_CREDENTIALS,
          clientCredentials: _anyCredentials,
          httpClient: _mockClient);

      // If the OAuth2 authentication is called
      OAuth2 handler = OAuth2(config);
      var token = await handler.authenticate();

      // Expect the valid token to be returned
      expect(token.accessToken, _ANY_ACCESS_TOKEN);
      expect(token.refreshToken, null);
      expect(token.expiration, isNot(null));
    });

    test('"password" returns token', () async {
      // Assuming that the client returns a valid token when calling
      // the authorization endpoint
      when(_mockClient.post(_anyAuthorizationEndpoint.toString(),
              data: anyNamed('data'), options: anyNamed('options')))
          .thenAnswer((_) => Future.value(Response(data: {
                ResponseDataField.ACCESS_TOKEN: _ANY_ACCESS_TOKEN,
                ResponseDataField.REFRESH_TOKEN: _ANY_REFRESH_TOKEN,
                ResponseDataField.EXPIRES_IN: _ANY_EXPIRES_IN,
                ResponseDataField.TOKEN_TYPE: _ANY_TOKEN_TYPE
              }, headers: _anyHeaders)));

      // And the authorization method is set to "password"
      var config = Config(
          authorizationEndpoint: _anyAuthorizationEndpoint,
          grantType: GrantType.PASSWORD,
          clientCredentials: _anyCredentials,
          userCredentials: _anyCredentials,
          httpClient: _mockClient);

      // If the OAuth2 authentication is called
      OAuth2 handler = OAuth2(config);
      var token = await handler.authenticate();

      // Expect the valid token to be returned
      expect(token.accessToken, _ANY_ACCESS_TOKEN);
      expect(token.refreshToken, _ANY_REFRESH_TOKEN);
      expect(token.expiration, isNotNull);
    });
  });

  group("Error response", () {
    test('with correct format throws AuthorizationException', () async {
      // Assuming that the client returns an error when calling
      // the authorization endpoint
      when(_mockClient.post(_anyAuthorizationEndpoint.toString(),
              data: anyNamed('data'), options: anyNamed('options')))
          .thenThrow(DioError(
              response: Response(data: {
        ResponseDataField.ERROR: _ANY_ERROR,
        ResponseDataField.ERROR_DESCRIPTION: _ANY_ERROR_DESCRIPTION,
        ResponseDataField.ERROR_URI: _anyErrorUri.toString()
      })));

      var config = Config(
          authorizationEndpoint: _anyAuthorizationEndpoint,
          grantType: GrantType.PASSWORD,
          clientCredentials: _anyCredentials,
          userCredentials: _anyCredentials,
          httpClient: _mockClient);

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

    test('with invalid format throws FormatException', () async {
      // Assuming that the client returns an invalid error when calling
      // the authorization endpoint
      when(_mockClient.post(_anyAuthorizationEndpoint.toString(),
              data: anyNamed('data'), options: anyNamed('options')))
          .thenThrow(DioError(response: Response(data: {})));

      var config = Config(
          authorizationEndpoint: _anyAuthorizationEndpoint,
          grantType: GrantType.PASSWORD,
          clientCredentials: _anyCredentials,
          userCredentials: _anyCredentials,
          httpClient: _mockClient);

      // If the OAuth2 authentication is called
      OAuth2 handler = OAuth2(config);
      try {
        // Expect the authentication to fail
        await handler.authenticate();
        fail("An FormatException is expected here!");
      } on FormatException catch (e) {
        // and to throw an exception
        expect(e.message, isNotNull);
      }
    });

    test('without response throws simple Exception', () async {
      // Assuming that the client returns an invalid error when calling
      // the authorization endpoint
      when(_mockClient.post(_anyAuthorizationEndpoint.toString(),
              data: anyNamed('data'), options: anyNamed('options')))
          .thenThrow(DioError());

      var config = Config(
          authorizationEndpoint: _anyAuthorizationEndpoint,
          grantType: GrantType.PASSWORD,
          clientCredentials: _anyCredentials,
          userCredentials: _anyCredentials,
          httpClient: _mockClient);

      // If the OAuth2 authentication is called
      OAuth2 handler = OAuth2(config);
      try {
        // Expect the authentication to fail
        await handler.authenticate();
        fail("An Exception is expected here!");
      } on Exception catch (e) {
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
          .thenAnswer(
              (_) => Future.value(Response(data: {}, headers: _anyHeaders)));

      var config = Config(
          authorizationEndpoint: _anyAuthorizationEndpoint,
          grantType: GrantType.PASSWORD,
          clientCredentials: _anyCredentials,
          userCredentials: _anyCredentials,
          httpClient: _mockClient);

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
          .thenAnswer((_) => Future.value(Response(data: {
                ResponseDataField.ACCESS_TOKEN: _ANY_ACCESS_TOKEN,
                ResponseDataField.EXPIRES_IN: _ANY_EXPIRES_IN,
                ResponseDataField.TOKEN_TYPE: _ANY_TOKEN_TYPE
              }, headers: _anyHeaders)));

      // and a token storage is put into the config
      var tokenStorage = MockTokenStorage();
      var config = Config(
          authorizationEndpoint: _anyAuthorizationEndpoint,
          grantType: GrantType.CLIENT_CREDENTIALS,
          clientCredentials: _anyCredentials,
          httpClient: _mockClient,
          tokenStorage: tokenStorage);

      // If the OAuth2 authentication is called with the reset flag
      OAuth2 handler = OAuth2(config);
      await handler.authenticate(reset: true);

      // Expect the clear method of the token storage to be called
      verify(tokenStorage.clear());
    });

    test('is used to read token if no token is in memory', () async {
      // Assuming that the client returns a valid token when calling
      // the authorization endpoint
      when(_mockClient.post(_anyAuthorizationEndpoint.toString(),
              data: anyNamed('data'), options: anyNamed('options')))
          .thenAnswer((_) => Future.value(Response(data: {
                ResponseDataField.ACCESS_TOKEN: _ANY_ACCESS_TOKEN,
                ResponseDataField.EXPIRES_IN: _ANY_EXPIRES_IN,
                ResponseDataField.TOKEN_TYPE: _ANY_TOKEN_TYPE
              }, headers: _anyHeaders)));

      // and a token storage is put into the config
      var tokenStorage = MockTokenStorage();
      when(tokenStorage.read()).thenAnswer((_) => Future.value(Token(
          _ANOTHER_ACCESS_TOKEN,
          _ANOTHER_REFRESH_TOKEN,
          DateTime.now().add(Duration(minutes: 10)))));
      var config = Config(
          authorizationEndpoint: _anyAuthorizationEndpoint,
          grantType: GrantType.CLIENT_CREDENTIALS,
          clientCredentials: _anyCredentials,
          httpClient: _mockClient,
          tokenStorage: tokenStorage);

      // If the OAuth2 authentication is called
      OAuth2 handler = OAuth2(config);
      var token = await handler.authenticate();

      // Expect the read method of the token storage to be called
      verify(tokenStorage.read());

      // Expect the valid token to be returned
      expect(token.accessToken, _ANOTHER_ACCESS_TOKEN);
      expect(token.refreshToken, _ANOTHER_REFRESH_TOKEN);
      expect(token.expiration, isNotNull);
    });

    test('is used to write token if new token is received', () async {
      // Assuming that the client returns a valid token when calling
      // the authorization endpoint
      when(_mockClient.post(_anyAuthorizationEndpoint.toString(),
              data: anyNamed('data'), options: anyNamed('options')))
          .thenAnswer((_) => Future.value(Response(data: {
                ResponseDataField.ACCESS_TOKEN: _ANY_ACCESS_TOKEN,
                ResponseDataField.EXPIRES_IN: _ANY_EXPIRES_IN,
                ResponseDataField.TOKEN_TYPE: _ANY_TOKEN_TYPE
              }, headers: _anyHeaders)));

      // and a token storage is put into the config
      var tokenStorage = MockTokenStorage();
      var config = Config(
          authorizationEndpoint: _anyAuthorizationEndpoint,
          grantType: GrantType.CLIENT_CREDENTIALS,
          clientCredentials: _anyCredentials,
          httpClient: _mockClient,
          tokenStorage: tokenStorage);

      // If the OAuth2 authentication is called
      OAuth2 handler = OAuth2(config);
      await handler.authenticate();

      // Expect the write method of the token storage to be called
      // after a new token is received
      verify(tokenStorage.write(argThat(isNotNull)));
    });

    test('is allowed to return empty value', () async {
      // Assuming that the client returns a valid token when calling
      // the authorization endpoint
      when(_mockClient.post(_anyAuthorizationEndpoint.toString(),
              data: anyNamed('data'), options: anyNamed('options')))
          .thenAnswer((_) => Future.value(Response(data: {
                ResponseDataField.ACCESS_TOKEN: _ANY_ACCESS_TOKEN,
                ResponseDataField.REFRESH_TOKEN: _ANY_REFRESH_TOKEN,
                ResponseDataField.EXPIRES_IN: _ANY_EXPIRES_IN,
                ResponseDataField.TOKEN_TYPE: _ANY_TOKEN_TYPE
              }, headers: _anyHeaders)));

      // and a token storage is put into the config
      var tokenStorage = MockTokenStorage();
      when(tokenStorage.read()).thenAnswer((_) => null);
      var config = Config(
          authorizationEndpoint: _anyAuthorizationEndpoint,
          grantType: GrantType.CLIENT_CREDENTIALS,
          clientCredentials: _anyCredentials,
          httpClient: _mockClient,
          tokenStorage: tokenStorage);

      // If the OAuth2 authentication is called
      OAuth2 handler = OAuth2(config);
      var token = await handler.authenticate();

      // Expect the valid token to be returned
      expect(token.accessToken, _ANY_ACCESS_TOKEN);
      expect(token.refreshToken, _ANY_REFRESH_TOKEN);
      expect(token.expiration, isNotNull);
    });
  });
}
