package io.swisty.middleware
import io.swisty.middleware._
import pdi.jwt.{JwtClaim}
import cats.effect._
import fs2.Stream
import org.http4s.client.Client
import org.http4s.implicits._
import org.http4s._
import org.http4s.dsl.Http4sDsl
import cats.data.Kleisli
import com.github.j5ik2o.base64scala.Base64StringFactory
import com.chatwork.scala.jwk._
import java.security.KeyPairGenerator
import java.security.KeyPair
import java.security.interfaces.RSAPublicKey

trait AuthMiddlewareFixture {
    val keyPair: KeyPair = {
    val keyGenerator = KeyPairGenerator.getInstance("RSA")
    keyGenerator.initialize(1024)
    keyGenerator.genKeyPair()
  }

  val modulos = {
    val publicKey = keyPair.getPublic().asInstanceOf[RSAPublicKey]
    publicKey.getModulus()
  }

  val exponent = {
    val publicKey = keyPair.getPublic().asInstanceOf[RSAPublicKey]
    publicKey.getPublicExponent()
  }

  val base64StringFactory = Base64StringFactory(urlSafe = true, isNoPadding = true)

  val thing = 1
  val audience = "http://someaudience.modaapps.com"

  def httpClient(body: String): Client[IO] = Client.apply[IO] { _ =>
    Resource.make(IO(Response[IO](body = Stream.emits(body.getBytes("UTF-8")))))(_ => IO.unit)
  }

  def service(r: Request[IO]) = for {
    jwskSetText <- IO(jwksetEither.map(f => f.toJsonString).getOrElse(""))
    jwkProvider <- JWKSProvider(audience, httpClient(jwskSetText))
    t            = authedRoutes(audience, jwkProvider)
    resp        <- t.run(r)
  } yield resp

  def authedRoutes(audience: String, jwkProvider: JWKSProvider[IO]): Kleisli[IO, Request[IO], Response[IO]] = {
    val dsl = new Http4sDsl[IO] {}
    import dsl._
    val middleware = JWTToken.authMiddleware(audience, jwkProvider)
    val routes = AuthedRoutes.of[JwtClaim, IO] { case authReq @ GET -> Root as user =>
      Ok(s"success ${user.issuer} ${authReq}")
    }
    middleware(routes).orNotFound
  }

  val keyId = "ABC1234"

  val sub = "AABBCCDDEEFF"

  val basicRequest = Request[IO](method = Method.GET, uri = uri"/")

  def jwksetEither = {
    for {
      n   <- base64StringFactory.encode(modulos)
      e   <- base64StringFactory.encode(exponent)
      jwk <- RSAJWK(n = n, e = e, publicKeyUse = Some(PublicKeyUseType.Signature), keyId = Some(KeyId(keyId)))
    } yield JWKSet(jwk)
  }


}
