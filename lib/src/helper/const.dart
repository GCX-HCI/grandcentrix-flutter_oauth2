/// Types of request / response headers used in OAuth 2.0
class HeaderTypeConst {
  static const CONTENT_TYPE = 'content-type';
  static const AUTHORIZATION = 'authorization';
}

/// Types of authorization headers used in OAuth 2.0
class AuthorizationTypeConst {
  static const BEARER = 'Bearer';
  static const BASIC = 'Basic';
}

/// Grant types included in OAuth 2.0
class GrantTypeConst {
  static const PASSWORD = 'password';
  static const CLIENT_CREDENTIALS = 'client_credentials';
  static const REFRESH_TOKEN = 'refresh_token';
  static const AUTHORIZATION_CODE = 'authorization_code';
}

/// Fields which are possibly included in a OAuth 2.0 response
class ResponseDataFieldConst {
  static const ACCESS_TOKEN = 'access_token';
  static const TOKEN_TYPE = 'token_type';
  static const EXPIRES_IN = 'expires_in';
  static const REFRESH_TOKEN = 'refresh_token';

  static const ERROR = 'error';
  static const ERROR_LIST = 'errors';
  static const ERROR_DESCRIPTION = 'error_description';
  static const ERROR_URI = 'error_uri';
  static const ERROR_CODE = 'code';
}

/// Fields which are possibly included in a OAuth 2.0 request
class RequestDataFieldConst {
  static const GRANT_TYPE = 'grant_type';
  static const USERNAME = 'username';
  static const PASSWORD = 'password';
  static const REFRESH_TOKEN = 'refresh_token';
  static const REDIRECT_URI = 'redirect_uri';
  static const CLIENT_ID = 'client_id';
  static const CLIENT_SECRET = 'client_secret';
  static const AUTHORIZATION_CODE = 'code';
}
