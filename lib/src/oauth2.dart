import 'package:dio/dio.dart';
import 'package:flutter_oauth2/src/helper/const.dart';
import 'package:flutter_oauth2/src/helper/exception.dart';
import 'package:flutter_oauth2/src/helper/utils.dart';
import 'package:flutter_oauth2/src/token/token.dart';

/// Credentials of any type e.g. client and user
class Credentials {
  String username;
  String password;

  Credentials(this.username, this.password);
}

/// Validates an error response and throws an exception in the end
_defaultErrorHandler(Response? response) {
  if (response == null || response.data is! Map) {
    throw FormatException('Response data cannot be read.');
  }

  Map data = response.data;

  if (!data.containsKey(ResponseDataFieldConst.ERROR) &&
      !data.containsKey(ResponseDataFieldConst.ERROR_LIST)) {
    throw FormatException(
        'did not contain required parameter "${ResponseDataFieldConst.ERROR}" or "${ResponseDataFieldConst.ERROR_LIST}"');
  } else if (data.containsKey(ResponseDataFieldConst.ERROR) &&
      data[ResponseDataFieldConst.ERROR] is! String) {
    throw FormatException(
        'required parameter "${ResponseDataFieldConst.ERROR}" was not a string, was '
        '"${data[ResponseDataFieldConst.ERROR]}"');
  } else if (data.containsKey(ResponseDataFieldConst.ERROR_LIST) &&
      data[ResponseDataFieldConst.ERROR_LIST] is! List) {
    throw FormatException(
        'required parameter "${ResponseDataFieldConst.ERROR_LIST}" was not a list, was '
        '"${data[ResponseDataFieldConst.ERROR_LIST]}"');
  }

  for (var name in [
    ResponseDataFieldConst.ERROR_DESCRIPTION,
    ResponseDataFieldConst.ERROR_URI
  ]) {
    var value = data[name];

    if (value != null && value is! String) {
      throw FormatException('parameter "$name" was not a string, was "$value"');
    }
  }

  // not standard OAuth
  if (data.containsKey(ResponseDataFieldConst.ERROR_LIST)) {
    throw AuthorizationException(
        data[ResponseDataFieldConst.ERROR_LIST][0]
            [ResponseDataFieldConst.ERROR_CODE],
        null,
        null);
  }

  throw AuthorizationException(
      data[ResponseDataFieldConst.ERROR],
      data.containsKey(ResponseDataFieldConst.ERROR_DESCRIPTION)
          ? data[ResponseDataFieldConst.ERROR_DESCRIPTION]
          : null,
      data.containsKey(ResponseDataFieldConst.ERROR_URI)
          ? Uri.parse(data[ResponseDataFieldConst.ERROR_URI])
          : null);
}

/// Handles the OAuth 2.0 flow.
/// It's the main class that you have to interact with.
class OAuth2 {
  OauthConfig _config;
  Token? _latestToken;

  OAuth2(this._config);

  /// Requests a token from the endpoint and returns it. Should be called before any HTTP call.
  ///
  /// If there is already a token available, the expiration will be checked.
  /// If the available token is expired, a new token will be requested by using the refresh token or by using the credentials.
  Future<Token?> authenticate({bool reset = false}) async {
    if (reset) {
      await _reset();
    }

    _latestToken = _latestToken ?? await _config.tokenStorage?.read();

    if (_latestToken == null) {
      _latestToken = await _getToken();
      await _onNewToken(_latestToken);
      return _latestToken;
    }

    if (_latestToken?.isExpired == true) {
      if (_latestToken?.refreshToken != null) {
        _latestToken = await _refreshToken(_latestToken?.refreshToken);
      } else {
        // If there is no refresh token, try to get a new token by credentials
        _latestToken = await _getToken();
      }
      await _onNewToken(_latestToken);
    }

    return _latestToken;
  }

  /// Resets all caches
  Future _reset() async {
    await _config.tokenStorage?.clear();
    _latestToken = null;
  }

  Future _onNewToken(Token? token) async {
    await _config.tokenStorage?.write(_latestToken);
  }

  /// Gets a new token considering the configured grant type
  Future<Token?> _getToken() async {
    if (_config.grantType == GrantType.REFRESH_TOKEN) {
      throw StateError(
          'Set GrantType to REFRESH_TOKEN, but cannot find token in TokenStorage');
    }

    return _requestToken(await _config.createTokenRequestBody());
  }

  /// Refreshes the current token by using the refresh token
  Future<Token?> _refreshToken(String? refreshToken) async {
    var body = {
      RequestDataFieldConst.GRANT_TYPE: GrantTypeConst.REFRESH_TOKEN,
      RequestDataFieldConst.REFRESH_TOKEN: refreshToken
    };

    return _requestToken(body);
  }

  /// General token request used to get and refresh token
  Future<Token?> _requestToken(var body) async {
    var startTime = DateTime.now();

    Options options = Options(
      contentType: Headers.formUrlEncodedContentType,
      headers: {},
    );
    if (_config.clientCredentials != null) {
      options.headers![HeaderTypeConst.AUTHORIZATION] = basicAuthHeader(
          _config.clientCredentials!.username,
          _config.clientCredentials!.password);
    }

    if (_config.additionalHeaders.isNotEmpty) {
      options.headers!.addAll(_config.additionalHeaders);
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
        throw Exception("Error when trying to send request");
      }
    }

    return null;
  }
}

abstract class OauthConfig {
  /// The endpoint to send the token request to
  final Uri authorizationEndpoint;

  /// The client credentials used to authorize
  final Credentials? clientCredentials;

  /// Grant type as defined by [GrantType]. Default is [GrantType.CLIENT_CREDENTIALS]
  final GrantType grantType;

  /// Storage to save token into. By default tokens are not saved
  final TokenStorage? tokenStorage;

  /// Function called when an error response is received. Default is validating OAuth 2.0 fields
  final Function(Response?) errorHandler;

  /// Additional headers to add to the token request
  late final Map<String, dynamic> additionalHeaders;

  /// The HTTP client to use
  late final Dio httpClient;

  Future<Map<String, dynamic>> createTokenRequestBody();

  OauthConfig({
    required GrantType this.grantType,
    required this.authorizationEndpoint,
    required this.clientCredentials,
    required Map<String, dynamic>? additionalHeaders,
    required this.tokenStorage,
    required this.errorHandler,
    required Dio? httpClient,
  }) {
    this.additionalHeaders = additionalHeaders ?? {};
    this.httpClient = httpClient ?? Dio();
  }
}

class OauthPasswordConfig extends OauthConfig {
  final GrantType grantType = GrantType.PASSWORD;

  /// The user credentials used to authorize.
  final Credentials userCredentials;

  OauthPasswordConfig({
    required this.userCredentials,
    required Uri authorizationEndpoint,
    clientCredentials,
    Map<String, dynamic>? additionalHeaders,
    TokenStorage? tokenStorage,
    Function(Response?)? errorHandler,
    Dio? httpClient,
  }) : super(
    grantType: GrantType.PASSWORD,
    authorizationEndpoint: authorizationEndpoint,
    clientCredentials: clientCredentials,
    additionalHeaders: additionalHeaders,
    tokenStorage: tokenStorage,
    errorHandler: errorHandler = _defaultErrorHandler,
    httpClient: httpClient,
  );

  @override
  Future<Map<String, dynamic>> createTokenRequestBody() async =>
      {
        RequestDataFieldConst.GRANT_TYPE: GrantTypeConst.PASSWORD,
        RequestDataFieldConst.USERNAME: userCredentials.username,
        RequestDataFieldConst.PASSWORD: userCredentials.password,
      };
}

class OauthClientCredentialsConfig extends OauthConfig {
  OauthClientCredentialsConfig({
    required Uri authorizationEndpoint,
    required Credentials clientCredentials,
    Map<String, dynamic>? additionalHeaders,
    TokenStorage? tokenStorage,
    Function(Response?)? errorHandler,
    Dio? httpClient,
  }) : super(
    grantType: GrantType.CLIENT_CREDENTIALS,
    authorizationEndpoint: authorizationEndpoint,
    clientCredentials: clientCredentials,
    additionalHeaders: additionalHeaders,
    tokenStorage: tokenStorage,
    errorHandler: errorHandler = _defaultErrorHandler,
    httpClient: httpClient,
  );

  @override
  Future<Map<String, dynamic>> createTokenRequestBody() async =>
      {
        RequestDataFieldConst.GRANT_TYPE: GrantTypeConst.CLIENT_CREDENTIALS,
      };
}
