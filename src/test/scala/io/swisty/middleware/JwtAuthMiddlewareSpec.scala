package io.swisty.middleware

import io.swisty.middleware._
import pdi.jwt.{JwtClaim}

import cats.effect.testing.scalatest.AsyncIOSpec
import org.scalatest.matchers.should.Matchers
import org.scalatest.freespec.AsyncFreeSpec
import org.http4s.headers._
import org.http4s._
import pdi.jwt._
import java.time.Instant

import java.time.temporal.ChronoUnit

class JwtAuthMiddlewareSpec extends AsyncFreeSpec with AsyncIOSpec with Matchers with AuthMiddlewareFixture {

  "JwtAuthMiddleware" - {
    "Request without authorization header" in {
      service(basicRequest).asserting(_.status shouldBe Status.Forbidden)
    }

    "Request with empty authorization header" in {
      service(basicRequest.putHeaders(Authorization(Credentials.Token(AuthScheme.Bearer, ""))))
        .asserting(_.status shouldBe Status.Forbidden)
    }

    "Valid json but not a JWT" in {
      service(basicRequest.putHeaders(Authorization(Credentials.Token(AuthScheme.Bearer, "{}"))))
        .asserting(_.status shouldBe Status.Forbidden)
    }

    "Invalid json / not a JWT" in {
      service(basicRequest.putHeaders(Authorization(Credentials.Token(AuthScheme.Bearer, "{"))))
        .asserting(_.status shouldBe Status.Forbidden)
    }

    "JWT credentials with incorrect KID" in {
      val header = new JwtHeader(Some(JwtAlgorithm.RS256), Some("JWT"), None, Some("A mismatched key"))
      val issuer = "bobo"

      val claim = new JwtClaim(
        "stuff",
        Some(issuer),
        Some(sub),
        Some(Set(audience)),
        Some(Instant.now().plus(1, ChronoUnit.HOURS).getEpochSecond()),
        None,
        Some(Instant.now().getEpochSecond()),
        Some(keyId)
      )
      service(
        basicRequest.putHeaders(
          Authorization(Credentials.Token(AuthScheme.Bearer, Jwt.encode(header, claim, keyPair.getPrivate())))
        )
      )
        .asserting(_.status shouldBe Status.Forbidden)
    }

    "Expired JWT credentials" in {
      val header = new JwtHeader(Some(JwtAlgorithm.RS256), Some("JWT"), None, Some(keyId))
      val issuer = "bobo"
      val claim = new JwtClaim(
        "stuff",
        Some(issuer),
        Some(sub),
        Some(Set(audience)),
        Some(Instant.now().minus(2, ChronoUnit.HOURS).getEpochSecond()),
        None,
        Some(Instant.now().minus(1, ChronoUnit.HOURS).getEpochSecond()),
        Some(keyId)
      )
      service(
        basicRequest.putHeaders(
          Authorization(Credentials.Token(AuthScheme.Bearer, Jwt.encode(header, claim, keyPair.getPrivate())))
        )
      )
        .asserting(_.status shouldBe Status.Forbidden)
    }

    "Valid JWT credentials" in {
      val header = new JwtHeader(Some(JwtAlgorithm.RS256), Some("JWT"), None, Some(keyId))
      val issuer = "bobo"
      val claim = new JwtClaim(
        "stuff",
        Some(issuer),
        Some(sub),
        Some(Set(audience)),
        Some(Instant.now().plus(1, ChronoUnit.HOURS).getEpochSecond()),
        None,
        Some(Instant.now().getEpochSecond()),
        Some(keyId)
      )

      service(
        basicRequest.putHeaders(
          Authorization(Credentials.Token(AuthScheme.Bearer, Jwt.encode(header, claim, keyPair.getPrivate())))
        )
      )
        .asserting(_.status shouldBe Status.Ok)
    }

    "Valid JWT credentials with audience" in {
      val header = new JwtHeader(Some(JwtAlgorithm.RS256), Some("JWT"), None, Some(keyId))
      val issuer = "bobo"
      val claim = new JwtClaim(
        "stuff",
        Some(issuer),
        Some(sub),
        Some(Set(audience)),
        Some(Instant.now().plus(1, ChronoUnit.HOURS).getEpochSecond()),
        None,
        Some(Instant.now().getEpochSecond()),
        Some(keyId)
      )
      service(
        basicRequest.putHeaders(
          Authorization(Credentials.Token(AuthScheme.Bearer, Jwt.encode(header, claim, keyPair.getPrivate())))
        ), Some(audience)
      )
        .asserting(_.status shouldBe Status.Ok)
    }
  }

  "Valid JWT credentials with incorrect audience" in {
    val header = new JwtHeader(Some(JwtAlgorithm.RS256), Some("JWT"), None, Some(keyId))
    val issuer = "bobo"
    val claim = new JwtClaim(
      "stuff",
      Some(issuer),
      Some(sub),
      Some(Set(audience)),
      Some(Instant.now().plus(1, ChronoUnit.HOURS).getEpochSecond()),
      None,
      Some(Instant.now().getEpochSecond()),
      Some(keyId)
    )
    service(
      basicRequest.putHeaders(
        Authorization(Credentials.Token(AuthScheme.Bearer, Jwt.encode(header, claim, keyPair.getPrivate())))
      ), Some("http://some-other-audience.swisty.io")
    )
      .asserting(_.status shouldBe Status.Forbidden)
  }
}
