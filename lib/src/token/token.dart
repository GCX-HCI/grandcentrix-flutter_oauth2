import 'package:dio/dio.dart';
import 'package:flutter_oauth2/src/helper/const.dart';

/// The amount of time to add as a "grace period" for credential expiration.
///
/// This allows credential expiration checks to remain valid for a reasonable
/// amount of time.
const _expirationGrace = Duration(seconds: 10);

/// OAuth 2.0 token information including access token, refresh token and expiration date
class Token {
  String accessToken;
  String? refreshToken;
  DateTime? expiration;

  Token(this.accessToken, this.refreshToken, this.expiration);

  /// Validates the response and creates a new [Token] object in the end
  factory Token.fromResponse(Response? response, DateTime? startTime) {
    if (response == null || response.data is! Map) {
      throw FormatException('Response data cannot be read.');
    }

    var data = response.data;

    var contentTypeString = response.headers[HeaderTypeConst.CONTENT_TYPE];
    if (contentTypeString == null) {
      throw FormatException('Missing Content-Type string.');
    }

    for (var requiredParameter in [
      ResponseDataFieldConst.ACCESS_TOKEN,
      ResponseDataFieldConst.TOKEN_TYPE
    ]) {
      if (!data.containsKey(requiredParameter)) {
        throw FormatException(
            'did not contain required parameter "$requiredParameter"');
      } else if (data[requiredParameter] is! String) {
        throw FormatException(
            'required parameter "$requiredParameter" was not a string, was '
            '"${data[requiredParameter]}"');
      }
    }

    if (data[ResponseDataFieldConst.TOKEN_TYPE].toLowerCase() !=
        AuthorizationTypeConst.BEARER.toLowerCase()) {
      throw FormatException(
          'Unknown token type "${data[ResponseDataFieldConst.TOKEN_TYPE]}"');
    }

    var expiresIn = data[ResponseDataFieldConst.EXPIRES_IN];
    if (expiresIn != null && expiresIn is! int) {
      throw FormatException(
          'parameter "${ResponseDataFieldConst.EXPIRES_IN}" was not an int, was "$expiresIn"');
    }

    var refreshToken = data[ResponseDataFieldConst.REFRESH_TOKEN];
    if (refreshToken != null && refreshToken is! String) {
      throw FormatException(
          'parameter "${ResponseDataFieldConst.REFRESH_TOKEN}" was not a string, was "$refreshToken"');
    }

    var expiration = expiresIn == null || startTime == null
        ? null
        : startTime.add(Duration(seconds: expiresIn) - _expirationGrace);

    return Token(
        data[ResponseDataFieldConst.ACCESS_TOKEN], refreshToken, expiration);
  }

  bool get isExpired =>
      expiration == null || DateTime.now().isAfter(expiration!);
}

/// Storage to save token persistently
abstract class TokenStorage {
  /// Write token
  Future write(Token? token);

  /// Read token
  Future<Token> read();

  /// Clears the current saved token
  Future clear();
}
