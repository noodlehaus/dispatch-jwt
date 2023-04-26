<?php declare(strict_types=1);

# creates JWT callable middleware
function jwt_middleware(
  string $secret,
  callable $fail = null,
  callable $validate = null
): callable {

  # set default validator that just says yes
  if ($validate === null) {
    $validate = fn() => true;
  }

  # default failure handler just returns 401
  if ($fail === null) {
    $fail = function () {
      http_response_code(401);
      print 'Invalid JWT';
      exit;
    };
  }

  # capture parameters into generated middleware function
  return function (callable $next, array $params, ...$args)
      use ($secret, $fail, $validate) {

    # right now, we only support 'Bearer <token>'
    $bearertxt = 'Bearer ';
    $headerval = $_SERVER['HTTP_AUTHORIZATION'] ?? null;

    if (empty($headerval)) {
      return $fail;
    }

    if (substr($headerval, 0, strlen($bearertxt)) !== $bearertxt) {
      return $fail();
    }

    $jwt = substr($headerval, strlen('Bearer '));
    if (!$validate($jwt, $secret)) {
      return $fail();
    }

    $data = jwt_decode($jwt, $secret);
    if (!$data) {
      return $fail();
    }

    return $next();
  };
}

# helper for encoding array payload
function jwt_encode(array $payload, string $secret): string {

  $head = json_encode(['typ' => 'JWT', 'alg' => 'HS256']);
  $data = json_encode($payload);

  $enchead = rtrim(strtr(base64_encode($head), '+/', '-_'), '=');
  $encdata = rtrim(strtr(base64_encode($data), '+/', '-_'), '=');

  $rawsign = hash_hmac('sha256', "{$enchead}.{$encdata}", $secret, true);
  $encsign = rtrim(strtr(base64_encode($rawsign), '+/', '-_'), '=');

  return "{$enchead}.{$encdata}.{$encsign}";
}

# helper for decoding payload using secret
function jwt_decode(string $jwt, string $secret): ?array {

  $parts = explode('.', $jwt);

  if (count($parts) !== 3) {
    return null;
  }

  [$enchead, $encdata, $encsig] = $parts;

  $head = json_decode(base64_decode(strtr($enchead, '-_', '+/')), true);
  $data = json_decode(base64_decode(strtr($encdata, '-_', '+/')), true);
  $sign = base64_decode(strtr($encsign, '-_', '+/'));

  $refsign = hash_hmac('sha256', "{$enchead}.{$encdata}", $secret, true);

  if (!hash_equals($sign, $refsign)) {
    return null;
  }

  return $data;
}
