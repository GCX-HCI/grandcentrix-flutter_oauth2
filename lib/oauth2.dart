import 'package:dio/dio.dart';
import 'package:flutter_oauth2/helper/const.dart';
import 'package:flutter_oauth2/helper/exception.dart';
import 'package:flutter_oauth2/helper/utils.dart';
import 'package:flutter_oauth2/token/token.dart';
import 'package:meta/meta.dart';

/// Credentials of any type e.g. client and user
class Credentials {
  String username;
  String password;

  Credentials(this.username, this.password);
}

/// Configuration for [OAuth2]
class Config {
  /// The endpoint to send the token request to
  Uri authorizationEndpoint;

  /// The client credentials used to authorize
  Credentials clientCredentials;

  /// The user credentials used to authorize. Only used if grant type is [GrantType.PASSWORD]
  Credentials userCredentials;

  /// Additional headers to add to the token request
  Map<String, dynamic> additionalHeaders;

  /// Grant type as defined by [GrantType]. Default is [GrantType.CLIENT_CREDENTIALS]
  GrantType grantType;

  /// Storage to save token into. By default tokens are not saved
  TokenStorage tokenStorage;

  /// Function called when an error response is received. Default is validating OAuth 2.0 fields
  Function(Response) errorHandler;

  /// The HTTP client to use
  Dio httpClient;

  Config(
      {@required this.authorizationEndpoint,
      this.grantType = GrantType.CLIENT_CREDENTIALS,
      @required this.clientCredentials,
      this.userCredentials,
      Map<String, dynamic> additionalHeaders,
      this.tokenStorage,
      this.errorHandler = _defaultErrorHandler,
      Dio httpClient}) {
    this.additionalHeaders = additionalHeaders ?? {};
    this.httpClient = httpClient ?? Dio();
  }
}

/// Validates an error response and throws an exception in the end
_defaultErrorHandler(Response response) {
  var data = response.data;

  if (!data.containsKey(ResponseDataFieldConst.ERROR) &&
      !data.containsKey(ResponseDataFieldConst.ERROR_LIST)) {
    throw new FormatException(
        'did not contain required parameter "${ResponseDataFieldConst.ERROR}" or "${ResponseDataFieldConst.ERROR_LIST}"');
  } else if (data.containsKey(ResponseDataFieldConst.ERROR) &&
      data[ResponseDataFieldConst.ERROR] is! String) {
    throw new FormatException(
        'required parameter "${ResponseDataFieldConst.ERROR}" was not a string, was '
        '"${data[ResponseDataFieldConst.ERROR]}"');
  } else if (data.containsKey(ResponseDataFieldConst.ERROR_LIST) &&
      data[ResponseDataFieldConst.ERROR_LIST] is! List) {
    throw new FormatException(
        'required parameter "${ResponseDataFieldConst.ERROR_LIST}" was not a list, was '
        '"${data[ResponseDataFieldConst.ERROR_LIST]}"');
  }

  for (var name in [
    ResponseDataFieldConst.ERROR_DESCRIPTION,
    ResponseDataFieldConst.ERROR_URI
  ]) {
    var value = data[name];

    if (value != null && value is! String) {
      throw new FormatException(
          'parameter "$name" was not a string, was "$value"');
    }
  }

  var error = data[ResponseDataFieldConst.ERROR];
  var description = data[ResponseDataFieldConst.ERROR_DESCRIPTION];
  var uri = Uri.parse(data[ResponseDataFieldConst.ERROR_URI]);
  throw new AuthorizationException(error, description, uri);
}

/// Handles the OAuth 2.0 flow.
/// It's the main class that you have to interact with.
class OAuth2 {
  Config _config;
  Token _latestToken;

  OAuth2(this._config) {
    if (this._config == null) {
      throw ArgumentError("Config cannot be null");
    }
  }

  /// Requests a token from the endpoint and returns it. Should be called before any HTTP call.
  ///
  /// If there is already a token available, the expiration will be checked.
  /// If the available token is expired, a new token will be requested by using the refresh token or by using the credentials.
  Future<Token> authenticate({bool reset = false}) async {
    if (reset) {
      await _reset();
    }

    if (_config.tokenStorage != null) {
      _latestToken = _latestToken ?? await _config.tokenStorage.read();
    }

    if (_latestToken == null) {
      _latestToken = await _getToken();
      await _onNewToken(_latestToken);
      return _latestToken;
    }

    if (_latestToken.isExpired) {
      if (_latestToken.refreshToken != null) {
        _latestToken = await _refreshToken(_latestToken.refreshToken);
        await _onNewToken(_latestToken);
      } else {
        // If there is no refresh token, try to get a new token by credentials
        _latestToken = await _getToken();
        await _onNewToken(_latestToken);
      }
    }

    return _latestToken;
  }

  /// Resets all caches
  Future _reset() async {
    if (_config.tokenStorage != null) {
      await _config.tokenStorage.clear();
    }
    _latestToken = null;
  }

  Future _onNewToken(Token token) async {
    if (_config.tokenStorage != null) {
      await _config.tokenStorage.write(_latestToken);
    }
  }

  /// Gets a new token considering the configured grant type
  Future<Token> _getToken() async {
    var body = _config.grantType == GrantType.CLIENT_CREDENTIALS
        ? {RequestDataFieldConst.GRANT_TYPE: GrantTypeConst.CLIENT_CREDENTIALS}
        : {
            RequestDataFieldConst.GRANT_TYPE: GrantTypeConst.PASSWORD,
            RequestDataFieldConst.USERNAME: _config.userCredentials.username,
            RequestDataFieldConst.PASSWORD: _config.userCredentials.password
          };

    return _requestToken(body);
  }

  /// Refreshes the current token by using the refresh token
  Future<Token> _refreshToken(var refreshToken) async {
    var body = {
      RequestDataFieldConst.GRANT_TYPE: GrantTypeConst.REFRESH_TOKEN,
      RequestDataFieldConst.REFRESH_TOKEN: refreshToken
    };

    return _requestToken(body);
  }

  /// General token request used to get and refresh token
  Future<Token> _requestToken(var body) async {
    var startTime = new DateTime.now();

    Options options = Options(contentType: Headers.formUrlEncodedContentType);
    options.headers[HeaderTypeConst.AUTHORIZATION] = basicAuthHeader(
        _config.clientCredentials.username, _config.clientCredentials.password);

    if (_config.additionalHeaders.isNotEmpty) {
      options.headers.addAll(_config.additionalHeaders);
    }

    try {
      var response = await _config.httpClient.post(
          _config.authorizationEndpoint.toString(),
          data: body,
          options: options);
      return Token.fromResponse(response, startTime);
    } on DioError catch (e) {
      if (e.response != null) {
        this._config.errorHandler(e.response);
      } else {
        throw new Exception("Error when trying to send request");
      }
    }

    return null;
  }
}
