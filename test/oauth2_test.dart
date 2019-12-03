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
  Credentials _credentials = Credentials("any", "any");
  Uri _authorizationEndpoint = Uri.https("mock.gcx", "/mockToken");

  test('Grant type "client_credentials" returns token', () async {
    when(_mockClient.post(_authorizationEndpoint.toString()))
        .thenAnswer((_) => Future.value(Response(data: {
              ResponseDataField.ACCESS_TOKEN: _ANY_ACCESS_TOKEN,
              ResponseDataField.REFRESH_TOKEN: _ANY_REFRESH_TOKEN,
              ResponseDataField.EXPIRES_IN: _ANY_EXPIRES_IN
            })));

    var config = Config(
        authorizationEndpoint: _authorizationEndpoint,
        grantType: GrantType.CLIENT_CREDENTIALS,
        clientCredentials: _credentials,
        httpClient: _mockClient);

    OAuth2 handler = OAuth2(config);

    var token = await handler.authenticate();
    expect(token.accessToken, _ANY_ACCESS_TOKEN);
    expect(token.refreshToken, _ANY_REFRESH_TOKEN);
    expect(token.expiration, _ANY_EXPIRES_IN);
  });
}
