import 'dart:convert';

import 'package:flutter_oauth2/helper/const.dart';

String basicAuthHeader(String identifier, String secret) =>
    '${AuthorizationType.BASIC} ' +
    base64Encode(utf8.encode('$identifier:$secret'));
