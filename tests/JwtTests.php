<?php declare(strict_types=1);

use PHPUnit\Framework\TestCase;

require_once __DIR__.'/../dispatch-jwt.php';

class JwtTests extends TestCase {

  private string $secret = 'my_secret_key';

  public function testJwtEncodeDecode(): void {
    $payload = ['user_id' => 1, 'email' => 'test@example.com'];
    $jwt = jwt_encode($payload, $this->secret);
    $decoded = jwt_decode($jwt, $this->secret);

    $this->assertSame($payload, $decoded);
  }

  public function testJwtDecodeInvalidSignature(): void {
    $payload = ['user_id' => 1, 'email' => 'test@example.com'];
    $jwt = jwt_encode($payload, $this->secret);
    $jwt = substr_replace($jwt, 'A', -1, 1); // tamper with the JWT signature

    $decoded = jwt_decode($jwt, $this->secret);
    $this->assertNull($decoded);
  }

  public function testJwtMiddleware(): void {
    $middleware = jwt_middleware($this->secret);
    $payload = ['user_id' => 1, 'email' => 'test@example.com'];
    $jwt = jwt_encode($payload, $this->secret);

    # simulate an HTTP request with a valid JWT
    $_SERVER['HTTP_AUTHORIZATION'] = "Bearer $jwt";

    $nextIsCalled = false;
    $next = function () use (&$nextIsCalled) {
      $nextIsCalled = true;
    };

    $middleware($next, []);
    $this->assertTrue($nextIsCalled);

    # test with an invalid JWT
    $_SERVER['HTTP_AUTHORIZATION'] = "Bearer invalid";
    $failCalled = false;
    $fail = function () use (&$failCalled) {
      $failCalled = true;
    };

    $middleware = jwt_middleware($this->secret, $fail);
    $middleware($next, []);
    $this->assertTrue($failCalled);
  }
}

