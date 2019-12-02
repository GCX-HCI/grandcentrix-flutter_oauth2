import 'package:dio/dio.dart';
import 'package:flutter_oauth2/helper/const.dart';
import 'package:flutter_oauth2/oauth2.dart';

/// [Dio] [Interceptor] which uses OAuth 2.0 to authenticate against a
/// server before sending a request.
class OAuth2DioInterceptor implements Interceptor {
  OAuth2 _handler;

  OAuth2DioInterceptor(Config configuration) {
    _handler = OAuth2(configuration);
  }

  @override
  Future onError(DioError error) async => error;

  @override
  Future onRequest(RequestOptions options) async {
    try {
      var token = await _handler.authenticate();

      // Add authorization header with bearer token
      options.headers[HeaderType.AUTHORIZATION] =
          "${AuthorizationType.BEARER} ${token.accessToken}";
    } catch (e) {
      return DioError(error: e);
    }

    return options;
  }

  @override
  Future onResponse(Response response) async => response;
}
