import 'package:dio/dio.dart';
import 'package:flutter_oauth2/const.dart';

/// The amount of time to add as a "grace period" for credential expiration.
///
/// This allows credential expiration checks to remain valid for a reasonable
/// amount of time.
const _expirationGrace = const Duration(seconds: 10);

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
      ResponseDataField.ACCESS_TOKEN,
      ResponseDataField.TOKEN_TYPE
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

    if (data[ResponseDataField.TOKEN_TYPE].toLowerCase() !=
        AuthorizationType.BEARER.toLowerCase()) {
      throw new FormatException(
          'Unknown token type "${data[ResponseDataField.TOKEN_TYPE]}"');
    }

    var expiresIn = data[ResponseDataField.EXPIRES_IN];
    if (expiresIn != null && expiresIn is! int) {
      throw new FormatException(
          'parameter "expires_in" was not an int, was "$expiresIn"');
    }

    var refreshToken = data[ResponseDataField.REFRESH_TOKEN];
    if (refreshToken != null && refreshToken is! String) {
      throw new FormatException(
          'parameter "refresh_token" was not a string, was "$refreshToken"');
    }

    var expiration = expiresIn == null
        ? null
        : startTime.add(new Duration(seconds: expiresIn) - _expirationGrace);

    return Token(
        data[ResponseDataField.ACCESS_TOKEN], refreshToken, expiration);
  }

  bool get isExpired =>
      expiration != null && new DateTime.now().isAfter(expiration);
}
