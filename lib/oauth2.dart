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
