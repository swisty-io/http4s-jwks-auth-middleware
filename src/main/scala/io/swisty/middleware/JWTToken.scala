package io.swisty.middleware
import pdi.jwt.{ JwtAlgorithm, JwtCirce, JwtClaim, JwtOptions }
import cats._
import cats.data._
import cats.implicits._
import org.http4s.server.AuthMiddleware
import cats.effect.concurrent.Ref
import cats.effect.Sync
import org.http4s.headers.Authorization
import org.http4s._
import org.http4s.circe._
import org.http4s.client._
import io.circe.generic.auto._
import com.chatwork.scala.jwk.{ JWK, JWKSet, KeyId, RSAJWK }
import java.net.http.HttpRequest

/**
  https://auth0.com/blog/navigating-rs256-and-jwks/#Verifying-a-JWT-using-the-JWKS-endpoint
  */
sealed trait TokenError extends Throwable
case class InvalidToken(
  message: String
) extends TokenError

trait JWKSProvider[F[_]] {
  def jwktSet: F[JWKSet]
}

object JWKSProvider {
  def apply[F[_]: Sync](subject: String, client: Client[F]): F[JWKSProvider[F]] = {
    val jwksUrl             = Uri.fromString(s"$subject.well-known/jwks.json")
    implicit val jwkDecoder = jsonOf[F, JWKSet]
    for {
      jwks <- Sync[F].fromEither(jwksUrl).flatMap(url => client.expect[JWKSet](url)(jwkDecoder))
      ref  <- Sync[F].delay(Ref.unsafe(jwks))
    } yield new JWKSProvider[F] {
      def jwktSet = ref.get
    }
  }
}

object JWTToken {

  def authUser[F[_]: Sync](
    audience: String,
    jwkProvider: JWKSProvider[F]
  ): Kleisli[F, Request[F], Either[String, JwtClaim]] = {

    def extractToken(req: Request[F]): Option[String] =
      req.headers.get(Authorization) collect {
        case Authorization(Credentials.Token(AuthScheme.Bearer, token)) => token
      }

    Kleisli { request: Request[F] =>
      val m = for {
        t <- jwkProvider.jwktSet
        token <- Sync[F].fromOption(extractToken(request), InvalidToken("bad"))
        (header, body, signature) <- Sync[F].fromTry(
                                      JwtCirce
                                        .decodeAll(
                                          token,
                                          JwtOptions.DEFAULT.copy(signature = false)
                                        )
                                    ) // is there an easier way to get the header?
        jwk <- Sync[F].fromOption(
                header.keyId.map(ds => t.keyByKeyId(KeyId(ds))),
                InvalidToken("no matching jwks")
              )
        m         <- Sync[F].fromOption(jwk, InvalidToken("bad"))
        d         <- Sync[F].delay(m.toPublicJWK.asInstanceOf[RSAJWK])
        publicKey <- Sync[F].fromEither(d.toPublicKey.leftMap(_ => InvalidToken("bad")))
        hh        <- Sync[F].fromTry(JwtCirce.decode(token, publicKey))
      } yield hh
      Sync[F]
        .attempt(m)
        .map(_.leftMap(_.getMessage()))
    }
  }

  def onFailure[F[_]: Sync]: AuthedRoutes[String, F] =
    Kleisli(e => OptionT.pure(Response[F](Status.Unauthorized)))

  def authMiddleware[F[_]: Sync](
    audience: String,
    jwkProvider: JWKSProvider[F]
  ) =
    AuthMiddleware(authUser(audience, jwkProvider), onFailure)
}
