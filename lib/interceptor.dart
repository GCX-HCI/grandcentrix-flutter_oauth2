import 'package:dio/dio.dart';
import 'package:flutter_oauth2/oauth2.dart';

class OAuth2Interceptor implements Interceptor {
  OAuth2 _handler;

  OAuth2Interceptor(Uri authorizationEndpoint, Credentials clientCredentials,
      Credentials userCredentials,
      [Map<String, String> additionalHeaders]) {
    _handler = OAuth2(authorizationEndpoint, clientCredentials, userCredentials,
        additionalHeaders);
  }

  @override
  Future onError(DioError error) async => error;

  @override
  Future onRequest(RequestOptions options) async {
    var token = await _handler.authenticate();

    options.headers[HeaderType.AUTHORIZATION] =
        "${AuthorizationType.BEARER} ${token.accessToken}";

    return options;
  }

  @override
  Future onResponse(Response response) async => response;
}
