import 'package:dio/dio.dart';
import 'package:flutter_oauth2/helper/const.dart';
import 'package:flutter_oauth2/oauth2.dart';
import 'package:mockito/mockito.dart';
import "package:test/test.dart";

class MockClient extends Mock implements Dio {}

void main() {
  const _ANY_ACCESS_TOKEN = "anyAccessToken";
  const _ANY_REFRESH_TOKEN = "anyRefreshToken";
  const _ANY_EXPIRES_IN = 123;
  const _ANY_TOKEN_TYPE = AuthorizationType.BEARER;
  const _ANY_CONTENT_TYPE = "anyContentType";

  Dio _mockClient = MockClient();
  Credentials _anyCredentials = Credentials("any", "any");
  Uri _anyAuthorizationEndpoint = Uri.https("mock.gcx", "/mockToken");
  Headers _anyHeaders = Headers();

  setUp(() {
    _anyHeaders.add(HeaderType.CONTENT_TYPE, _ANY_CONTENT_TYPE);
  });

  test('Grant type "client_credentials" returns token', () async {
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

  test('Grant type "password" returns token', () async {
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

    // And the authorization method is set to "client_credentials"
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
    expect(token.expiration, isNot(null));
  });
}
