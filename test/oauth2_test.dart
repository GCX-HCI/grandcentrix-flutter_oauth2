import 'package:dio/dio.dart';
import 'package:flutter_oauth2/helper/const.dart';
import 'package:flutter_oauth2/oauth2.dart';
import 'package:mockito/mockito.dart';
import "package:test/test.dart";

class MockClient extends Mock implements Dio {}

void main() {
  const _ANY_ACCESS_TOKEN = "anyAccessToken";
  const _ANY_REFRESH_TOKEN = "anyRefreshToken";
  const _ANY_EXPIRES_IN = "123";

  Dio _mockClient = MockClient();
  Credentials _anyCredentials = Credentials("any", "any");
  Uri _anyAuthorizationEndpoint = Uri.https("mock.gcx", "/mockToken");

  test('Grant type "client_credentials" returns token', () async {
    // Assuming that the client returns a valid token when calling
    // the authorization endpoint
    when(_mockClient.post(_anyAuthorizationEndpoint.toString()))
        .thenAnswer((_) => Future.value(Response(data: {
              ResponseDataField.ACCESS_TOKEN: _ANY_ACCESS_TOKEN,
              ResponseDataField.REFRESH_TOKEN: _ANY_REFRESH_TOKEN,
              ResponseDataField.EXPIRES_IN: _ANY_EXPIRES_IN
            })));

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
    expect(token.refreshToken, _ANY_REFRESH_TOKEN);
    expect(token.expiration, _ANY_EXPIRES_IN);
  });
}
