import 'dart:convert';

import 'package:dio/dio.dart';

/// The amount of time to add as a "grace period" for credential expiration.
///
/// This allows credential expiration checks to remain valid for a reasonable
/// amount of time.
const _expirationGrace = const Duration(seconds: 10);

/// Credentials of any type e.g. client and user
class Credentials {
  String username;
  String password;

  Credentials(this.username, this.password);
}

/// Types of request / response headers used in OAuth 2.0
class HeaderType {
  static const CONTENT_TYPE = 'content-type';
  static const AUTHORIZATION = 'authorization';
}

/// Types of authorization headers used in OAuth 2.0
class AuthorizationType {
  static const BEARER = 'Bearer';
  static const BASIC = 'Basic';
}

/// Fields which are possibly included in a OAuth 2.0 response
class _ResponseDataField {
  static const ACCESS_TOKEN = 'access_token';
  static const TOKEN_TYPE = 'token_type';
  static const EXPIRES_IN = 'expires_in';
  static const REFRESH_TOKEN = 'refresh_token';

  static const ERROR = 'error';
  static const ERROR_LIST = 'errors';
  static const ERROR_DESCRIPTION = 'error_description';
  static const ERROR_URI = 'error_uri';
}

/// Fields which are possibly included in a OAuth 2.0 request
class _RequestDataField {
  static const GRANT_TYPE = 'grant_type';
  static const USERNAME = 'username';
  static const PASSWORD = 'password';
  static const REFRESH_TOKEN = 'refresh_token';
}

/// Grant types included in OAuth 2.0
class _GrantType {
  static const PASSWORD = 'password';
  static const CLIENT_CREDENTIALS = 'client_credentials';
  static const REFRESH_TOKEN = 'refresh_token';
}

/// OAuth 2.0 token information including access token, refresh token and expiration date
class Token {
  String accessToken;
  String refreshToken;
  DateTime expiration;

  /// Validates the response and creates a new [Token] object in the end
  factory Token(Response response, DateTime startTime) {
    if (response == null || response.data is! Map) {
      throw new FormatException('Response data cannot be read.');
    }

    var data = response.data;

    var contentTypeString = response.headers[HeaderType.CONTENT_TYPE];
    if (contentTypeString == null) {
      throw new FormatException('Missing Content-Type string.');
    }

    for (var requiredParameter in [
      _ResponseDataField.ACCESS_TOKEN,
      _ResponseDataField.TOKEN_TYPE
    ]) {
      if (!data.containsKey(requiredParameter)) {
        throw new FormatException(
            'did not contain required parameter "$requiredParameter"');
      } else if (data[requiredParameter] is! String) {
        throw new FormatException(
            'required parameter "$requiredParameter" was not a string, was '
            '"${data[requiredParameter]}"');
      }
    }

    if (data[_ResponseDataField.TOKEN_TYPE].toLowerCase() !=
        AuthorizationType.BEARER.toLowerCase()) {
      throw new FormatException(
          'Unknown token type "${data[_ResponseDataField.TOKEN_TYPE]}"');
    }

    var expiresIn = data[_ResponseDataField.EXPIRES_IN];
    if (expiresIn != null && expiresIn is! int) {
      throw new FormatException(
          'parameter "expires_in" was not an int, was "$expiresIn"');
    }

    var refreshToken = data[_ResponseDataField.REFRESH_TOKEN];
    if (refreshToken != null && refreshToken is! String) {
      throw new FormatException(
          'parameter "refresh_token" was not a string, was "$refreshToken"');
    }

    var expiration = expiresIn == null
        ? null
        : startTime.add(new Duration(seconds: expiresIn) - _expirationGrace);

    return Token._internal(
        data[_ResponseDataField.ACCESS_TOKEN], refreshToken, expiration);
  }

  Token._internal(this.accessToken, this.refreshToken, this.expiration);

  bool get isExpired =>
      expiration != null && new DateTime.now().isAfter(expiration);
}

class OAuth2 {
  Dio _httpClient = Dio();

  Uri _authorizationEndpoint;
  Credentials _clientCredentials;
  Credentials _userCredentials;
  Map<String, String> _additionalHeaders;
  String _grantType;

  Token _latestToken;

  OAuth2(this._authorizationEndpoint, this._clientCredentials,
      [this._grantType = _GrantType.CLIENT_CREDENTIALS,
      this._userCredentials,
      this._additionalHeaders]);

  // TODO get rid of RequestOptions here
  Future<Token> authenticate() async {
    // TODO save refresh token safely on device and restore it
    if (_latestToken != null) {
      if (_latestToken.isExpired) {
        _latestToken = await _refreshToken(_latestToken.refreshToken);
      }
    } else {
      _latestToken = await _getToken();
    }

    return _latestToken;
  }

  Future<Token> _getToken() async {
    var body = _grantType == _GrantType.CLIENT_CREDENTIALS
        ? {_RequestDataField.GRANT_TYPE: _GrantType.CLIENT_CREDENTIALS}
        : {
            _RequestDataField.GRANT_TYPE: _GrantType.PASSWORD,
            _RequestDataField.USERNAME: _userCredentials.username,
            _RequestDataField.PASSWORD: _userCredentials.password
          };

    return _requestToken(body);
  }

  Future<Token> _refreshToken(var refreshToken) async {
    var body = {
      _RequestDataField.GRANT_TYPE: _GrantType.REFRESH_TOKEN,
      _RequestDataField.REFRESH_TOKEN: refreshToken
    };

    return _requestToken(body);
  }

  Future<Token> _requestToken(var body) async {
    var startTime = new DateTime.now();

    Options options = Options(contentType: Headers.formUrlEncodedContentType);
    options.headers[HeaderType.AUTHORIZATION] = _basicAuthHeader(
        _clientCredentials.username, _clientCredentials.password);

    if (_additionalHeaders != null && _additionalHeaders.isNotEmpty) {
      options.headers.addAll(_additionalHeaders);
    }

    try {
      var response = await _httpClient.post(_authorizationEndpoint.toString(),
          data: body, options: options);
      return Token(response, startTime);
    } catch (e) {
      if (e.response != null) {
        _handleResponseError(e.response);
      } else {
        throw new Exception("Error when trying to send request");
      }
    }

    return null;
  }

  String _basicAuthHeader(String identifier, String secret) =>
      '${AuthorizationType.BASIC} ' +
      base64Encode(utf8.encode('$identifier:$secret'));

  void _handleResponseError(Response response) {
    var data = response.data;

    if (!data.containsKey(_ResponseDataField.ERROR) &&
        !data.containsKey(_ResponseDataField.ERROR_LIST)) {
      throw new FormatException(
          'did not contain required parameter "error" or "errors"');
    } else if (data.containsKey(_ResponseDataField.ERROR) &&
        data[_ResponseDataField.ERROR] is! String) {
      throw new FormatException(
          'required parameter "error" was not a string, was '
          '"${data[_ResponseDataField.ERROR]}"');
    } else if (data.containsKey(_ResponseDataField.ERROR_LIST) &&
        data[_ResponseDataField.ERROR_LIST] is! List) {
      throw new FormatException(
          'required parameter "errors" was not a map, was '
          '"${data[_ResponseDataField.ERROR_LIST]}"');
    }

    for (var name in [
      _ResponseDataField.ERROR_DESCRIPTION,
      _ResponseDataField.ERROR_URI
    ]) {
      var value = data[name];

      if (value != null && value is! String) {
        throw new FormatException(
            'parameter "$name" was not a string, was "$value"');
      }
    }

    var description = data[_ResponseDataField.ERROR_DESCRIPTION];
    throw new Exception(description);
  }
}
