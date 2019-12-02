import 'dart:convert';

import 'package:dio/dio.dart';
import 'package:flutter_secure_storage/flutter_secure_storage.dart' as store;

/// The amount of time to add as a "grace period" for credential expiration.
///
/// This allows credential expiration checks to remain valid for a reasonable
/// amount of time.
const _expirationGrace = const Duration(seconds: 10);

class AuthorizationException implements Exception {
  final String error;
  final String description;
  final Uri uri;

  AuthorizationException(this.error, this.description, this.uri);

  @override
  String toString() {
    return "$error: $description (${uri.toString()})";
  }
}

class ExpirationException implements Exception {
  Token token;

  ExpirationException(this.token);
}

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

/// Grant types included in OAuth 2.0
class GrantType {
  static const PASSWORD = 'password';
  static const CLIENT_CREDENTIALS = 'client_credentials';
  static const REFRESH_TOKEN = 'refresh_token';
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

/// Storage to save token persistently
abstract class TokenStorage {
  /// Write token
  Future write(Token token);

  /// Read token
  Future<Token> read();

  /// Clears the current saved token
  Future clear();
}

/// Default implementation of [TokenStorage] using encryption
///
/// See https://github.com/mogol/flutter_secure_storage for usage requirements
class DefaultTokenStorage implements TokenStorage {
  static const _ACCESS_TOKEN_KEY = "oauth2_access_token";
  static const _REFRESH_TOKEN_KEY = "oauth2_refresh_token";
  static const _KEY_EXPIRATION = "oauth2_expiration";

  store.FlutterSecureStorage _storage;

  DefaultTokenStorage() {
    _storage = new store.FlutterSecureStorage();
  }

  @override
  Future<Token> read() async {
    var accessToken = await _storage.read(key: _ACCESS_TOKEN_KEY);
    var refreshToken = await _storage.read(key: _REFRESH_TOKEN_KEY);
    var expiration = await _storage.read(key: _KEY_EXPIRATION);

    if (accessToken == null || refreshToken == null) {
      return null;
    }

    if (expiration == null) {
      expiration = DateTime.now().millisecondsSinceEpoch.toString();
    }

    return Token(accessToken, refreshToken,
        DateTime.fromMillisecondsSinceEpoch(int.parse(expiration)));
  }

  @override
  Future write(Token token) async {
    await _storage.write(key: _ACCESS_TOKEN_KEY, value: token.accessToken);
    await _storage.write(key: _REFRESH_TOKEN_KEY, value: token.refreshToken);
    await _storage.write(
        key: _KEY_EXPIRATION,
        value: token.expiration.millisecondsSinceEpoch.toString());
  }

  @override
  Future clear() async {
    await _storage.delete(key: _ACCESS_TOKEN_KEY);
    await _storage.delete(key: _REFRESH_TOKEN_KEY);
    await _storage.delete(key: _KEY_EXPIRATION);
  }
}

/// OAuth 2.0 token information including access token, refresh token and expiration date
class Token {
  String accessToken;
  String refreshToken;
  DateTime expiration;

  Token(this.accessToken, this.refreshToken, this.expiration);

  /// Validates the response and creates a new [Token] object in the end
  factory Token.fromResponse(Response response, DateTime startTime) {
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

    return Token(
        data[_ResponseDataField.ACCESS_TOKEN], refreshToken, expiration);
  }

  bool get isExpired =>
      expiration != null && new DateTime.now().isAfter(expiration);
}

/// Configuration for [OAuth2]
class Config {
  /// The endpoint to send the token request to
  Uri authorizationEndpoint;

  /// The client credentials used to authorize
  Credentials clientCredentials;

  /// The user credentials used to authorize. Only used if grant type is 'password'
  Credentials userCredentials;

  /// Additional headers to add to the token request
  Map<String, dynamic> additionalHeaders;

  /// Grant type as defined by [GrantType]. Default is [GrantType.CLIENT_CREDENTIALS]
  String grantType;

  /// Storage to save token into. Default is [DefaultTokenStorage]
  TokenStorage tokenStorage;

  Config(
      {this.authorizationEndpoint,
      this.clientCredentials,
      this.grantType = GrantType.CLIENT_CREDENTIALS,
      this.userCredentials,
      Map<String, dynamic> additionalHeaders,
      TokenStorage tokenStorage}) {
    this.additionalHeaders = additionalHeaders ?? {};
    this.tokenStorage = tokenStorage ?? DefaultTokenStorage();
  }
}

/// Handles the OAuth 2.0 flow.
/// It's the main class that you have to interact with.
class OAuth2 {
  Dio _httpClient = Dio();
  Config _config;
  Token _latestToken;

  OAuth2(this._config);

  /// Requests a token from the endpoint and returns it.
  ///
  /// If there is already a token available, the expiration will be checked.
  /// If the available token is expired, a new token will be requested by using the refresh token.
  Future<Token> authenticate() async {
    if (_config.tokenStorage != null) {
      _latestToken = _latestToken ?? await _config.tokenStorage.read();
    }

    if (_latestToken == null) {
      _latestToken = await _getToken();
    }

    if (_latestToken.isExpired) {
      if (_latestToken.refreshToken != null) {
        _latestToken = await _refreshToken(_latestToken.refreshToken);
      } else {
        throw new ExpirationException(_latestToken);
      }
    }

    await _config.tokenStorage.write(_latestToken);
    return _latestToken;
  }

  /// Gets a new token considering the configured grant type
  Future<Token> _getToken() async {
    var body = _config.grantType == GrantType.CLIENT_CREDENTIALS
        ? {_RequestDataField.GRANT_TYPE: GrantType.CLIENT_CREDENTIALS}
        : {
            _RequestDataField.GRANT_TYPE: GrantType.PASSWORD,
            _RequestDataField.USERNAME: _config.userCredentials.username,
            _RequestDataField.PASSWORD: _config.userCredentials.password
          };

    return _requestToken(body);
  }

  /// Refreshs the current token by using the refresh token
  Future<Token> _refreshToken(var refreshToken) async {
    var body = {
      _RequestDataField.GRANT_TYPE: GrantType.REFRESH_TOKEN,
      _RequestDataField.REFRESH_TOKEN: refreshToken
    };

    return _requestToken(body);
  }

  /// General token request used to get and refresh token
  Future<Token> _requestToken(var body) async {
    var startTime = new DateTime.now();

    Options options = Options(contentType: Headers.formUrlEncodedContentType);
    options.headers[HeaderType.AUTHORIZATION] = _basicAuthHeader(
        _config.clientCredentials.username, _config.clientCredentials.password);

    if (_config.additionalHeaders.isNotEmpty) {
      options.headers.addAll(_config.additionalHeaders);
    }

    try {
      var response = await _httpClient.post(
          _config.authorizationEndpoint.toString(),
          data: body,
          options: options);
      return Token.fromResponse(response, startTime);
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

  /// Validates an error response and throws an exception in the end
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

    var error = data[_ResponseDataField.ERROR];
    var description = data[_ResponseDataField.ERROR_DESCRIPTION];
    var uri = data[_ResponseDataField.ERROR_URI];
    throw new AuthorizationException(error, description, uri);
  }
}
