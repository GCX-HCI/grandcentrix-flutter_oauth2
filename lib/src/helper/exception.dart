import 'package:flutter_oauth2/src/token/token.dart';

class AuthorizationException implements Exception {
  final String? error;
  final String? description;
  final Uri? uri;

  AuthorizationException(this.error, this.description, this.uri);

  @override
  String toString() =>
      "${this.runtimeType.toString()}($error: $description (${uri.toString()}))";
}

class ExpirationException implements Exception {
  Token token;

  ExpirationException(this.token);
}
