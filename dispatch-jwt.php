<?php declare(strict_types=1);

# creates JWT callable middleware
function jwt_middleware(string $secret): callable {
  return fn(callable $next, array $params, ...$args) use ($secret) {
  };
}

# helper for encoding array payload
function jwt_encode(array $payload, string $secret): string {
  return '';
}

# helper for decoding payload using secret
function jwt_decode(string $jwt, string $secret): ?array {
  return [];
}
