import 'package:flutter_oauth2/token/token.dart';
import 'package:flutter_secure_storage/flutter_secure_storage.dart';

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

  FlutterSecureStorage _storage;

  DefaultTokenStorage() {
    _storage = new FlutterSecureStorage();
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
