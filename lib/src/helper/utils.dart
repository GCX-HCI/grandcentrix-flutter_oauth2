import 'dart:convert';

import 'package:flutter_oauth2/src/helper/const.dart';

String basicAuthHeader(String identifier, String secret) =>
    '${AuthorizationTypeConst.BASIC} ' +
    base64Encode(utf8.encode('$identifier:$secret'));
