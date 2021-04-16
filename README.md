# flutter_oauth2
OAuth 2.0 library for Flutter / Dart

## Get started

### Add dependency

```yaml
dependencies:
  flutter_oauth2:
      git:
        url: git@github.com:GCX-HCI/grandcentrix-flutter_oauth2.git
        ref: v0.1.2
```

### Simple to use

```dart
import 'package:flutter_oauth2/flutter_oauth2.dart';

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

## Contribute

### Test Mocks

This project makes use of the Mockito library. To ensure null safety, Mockito has to generate Mocks using the build_runner. 
To regenerate Mocks, just call
```
pub run build_runner build
```