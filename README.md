# flutter_oauth2
OAuth 2.0 library for Flutter / Dart

## Get started

### Add dependency

```yaml
dependencies:
  flutter_oauth2:
      git:
        url: git@github.gcxi.de:grandcentrix/flutter_oauth2.git
        ref: v0.1.0
```

### Simple to use

```dart
import 'package:flutter_oauth2/helper/const.dart';
import 'package:flutter_oauth2/token/token.dart';
import 'package:flutter_oauth2/oauth2.dart';

OAuth2 handler = OAuth2(Config(
        authorizationEndpoint: endpointUri,
        grantType: GrantType.PASSWORD,
        clientCredentials: Credentials(clientId, clientSecret),
        userCredentials: Credentials(username, password)));

try {
  Token token = await handler.authenticate();
  // do something with the token
} catch (e) {}
```
