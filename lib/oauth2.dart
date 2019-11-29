import 'dart:convert';

import 'package:dio/dio.dart';

/// The amount of time to add as a "grace period" for credential expiration.
///
/// This allows credential expiration checks to remain valid for a reasonable
/// amount of time.
const _expirationGrace = const Duration(seconds: 10);

class Credentials {
  String username;
  String password;

  Credentials(this.username, this.password);
}

class Token {
  String accessToken;
  String refreshToken;
  DateTime expiration;

  Token(this.accessToken, this.refreshToken, this.expiration);

  bool get isExpired =>
      expiration != null && new DateTime.now().isAfter(expiration);

  static from(Response response, DateTime startTime) {
    if (response == null || response.data is! Map) {
      throw new FormatException('Response data cannot be read.');
    }

    var data = response.data;

    var contentTypeString = response.headers['content-type'];
    if (contentTypeString == null) {
      throw new FormatException('Missing Content-Type string.');
    }

    for (var requiredParameter in ['access_token', 'token_type']) {
      if (!data.containsKey(requiredParameter)) {
        throw new FormatException(
            'did not contain required parameter "$requiredParameter"');
      } else if (data[requiredParameter] is! String) {
        throw new FormatException(
            'required parameter "$requiredParameter" was not a string, was '
            '"${data[requiredParameter]}"');
      }
    }

    if (data['token_type'].toLowerCase() != 'bearer') {
      throw new FormatException('Unknown token type "${data['token_type']}"');
    }

    var expiresIn = data['expires_in'];
    if (expiresIn != null && expiresIn is! int) {
      throw new FormatException(
          'parameter "expires_in" was not an int, was "$expiresIn"');
    }

    for (var name in ['refresh_token', 'id_token', 'scope']) {
      var value = data[name];
      if (value != null && value is! String) {
        throw new FormatException(
            'parameter "$name" was not a string, was "$value"');
      }
    }

    var expiration = expiresIn == null
        ? null
        : startTime.add(new Duration(seconds: expiresIn) - _expirationGrace);

    return Token(data['access_token'], data['refresh_token'], expiration);
  }
}

class OAuth2Interceptor implements Interceptor {
  Dio _httpClient = Dio();

  Uri _authorizationEndpoint;
  Credentials _clientCredentials;
  Credentials _userCredentials;
  Map<String, String> _additionalHeaders;
  Token _latestToken;

  OAuth2Interceptor(this._authorizationEndpoint, this._clientCredentials,
      this._userCredentials,
      [this._additionalHeaders]);

  @override
  Future onError(DioError error) async => error;

  @override
  Future onRequest(RequestOptions options) async =>
      await _authenticate(options);

  @override
  Future onResponse(Response response) async => response;

  Future<RequestOptions> _authenticate(RequestOptions options) async {
    // TODO save refresh token safely on device and restore it
    if (_latestToken != null) {
      if (_latestToken.isExpired) {
        _latestToken = await _refreshToken(_latestToken.refreshToken);
      }
    } else {
      _latestToken = await _getToken();
    }

    options.headers['authorization'] = "Bearer ${_latestToken.accessToken}";

    return options;
  }

  Future<Token> _getToken() async {
    var body = {
      'grant_type': 'password',
      'username': _userCredentials.username,
      'password': _userCredentials.password
    };

    return _requestToken(body);
  }

  Future<Token> _refreshToken(var refreshToken) async {
    var body = {'grant_type': 'refresh_token', 'refresh_token': refreshToken};

    return _requestToken(body);
  }

  Future<Token> _requestToken(var body) async {
    var startTime = new DateTime.now();

    Options options = Options(contentType: Headers.formUrlEncodedContentType);
    options.headers['authorization'] = basicAuthHeader(
        _clientCredentials.username, _clientCredentials.password);

    if (_additionalHeaders != null && _additionalHeaders.isNotEmpty) {
      options.headers.addAll(_additionalHeaders);
    }

    try {
      var response = await _httpClient.post(_authorizationEndpoint.toString(),
          data: body, options: options);
      return Token.from(response, startTime);
    } catch (e) {
      if (e.response != null) {
        _handleResponseError(e.response);
      } else {
        throw new Exception("Error when trying to send request");
      }
    }

    return null;
  }

  String basicAuthHeader(String identifier, String secret) =>
      'Basic ' + base64Encode(utf8.encode('$identifier:$secret'));

  void _handleResponseError(Response response) {
    var data = response.data;

    if (!data.containsKey('error') && !data.containsKey('errors')) {
      throw new FormatException(
          'did not contain required parameter "error" or "errors"');
    } else if (data.containsKey('error') && data['error'] is! String) {
      throw new FormatException(
          'required parameter "error" was not a string, was '
          '"${data["error"]}"');
    } else if (data.containsKey('errors') && data['errors'] is! List) {
      throw new FormatException('required parameter "error" was not a map, was '
          '"${data["error"]}"');
    }

    for (var name in ['error_description', 'error_uri']) {
      var value = data[name];

      if (value != null && value is! String) {
        throw new FormatException(
            'parameter "$name" was not a string, was "$value"');
      }
    }

    var description = data['error_description'];
    throw new Exception(description);
  }
}
