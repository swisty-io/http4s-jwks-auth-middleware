package io.swisty.middleware
import pdi.jwt.{JwtCirce, JwtClaim, JwtOptions}
import cats.data._
import cats.implicits._
import org.http4s.server.AuthMiddleware
import cats.effect._
import org.http4s.headers.Authorization
import org.http4s._
import org.http4s.circe._
import org.http4s.client._
import io.circe.generic.auto._
import com.chatwork.scala.jwk.{JWKSet, KeyId, RSAJWK}

/**
 *  https://auth0.com/blog/navigating-rs256-and-jwks/#Verifying-a-JWT-using-the-JWKS-endpoint
 */
sealed trait TokenError extends Throwable
final case class InvalidCredentials(message: String) extends Exception(message) with TokenError
final case class ExpiredCredentials(message: String) extends Exception(message) with TokenError
trait JWKSProvider[F[_]] {
  def jwktSet: F[JWKSet]
}

object JWKSProvider {
  def apply[F[_]: Async](subject: String, client: Client[F]): F[JWKSProvider[F]] = {
    implicit val authResponseEntityDecoder: EntityDecoder[F, JWKSet] = jsonOf[F, JWKSet]
    val jwksUrl: ParseResult[Uri] = Uri.fromString(s"$subject.well-known/jwks.json")
    for {
      jwks       <- Async[F].fromEither(jwksUrl)
      jwksResult <- client.expect[JWKSet](jwks)(authResponseEntityDecoder)
      ref        <- Async[F].delay(Ref.unsafe(jwksResult))
    } yield new JWKSProvider[F] {
      def jwktSet =
        ref.get
    }
  }
}
object JWTToken {
  def authUser[F[_]: Sync](
    audience: Option[String],
    jwkProvider: JWKSProvider[F]
  ): Kleisli[F, Request[F], Either[String, JwtClaim]] = {

    def extractToken(req: Request[F]): Option[String] =
      req.headers.get[Authorization] collect { case Authorization(Credentials.Token(AuthScheme.Bearer, token)) =>
        token
      }

    def maybeClaimMatchingAudience(jwtCkaim: JwtClaim, audience: Option[String]): F[JwtClaim] =
      audience.zip(jwtCkaim.audience) match {
        case None                   => Sync[F].delay(jwtCkaim)
        case Some((aud, audiences)) =>
          if (audiences.contains(aud)) {
            println("CFM: it matched!!!!!")
            Sync[F].delay(jwtCkaim)
          } else {
            Sync[F].raiseError[JwtClaim](InvalidCredentials("missing/mismatched audience"))
          }
      }

    Kleisli { request: Request[F] =>
      val claim = for {
        jwtSet         <- jwkProvider.jwktSet
        token          <- Sync[F].fromOption(extractToken(request), InvalidCredentials("unable to extract token"))
        (header, _, _) <- Sync[F].fromTry(
                            JwtCirce
                              .decodeAll(
                                token,
                                JwtOptions.DEFAULT.copy(signature = false)
                              )
                          ) // is there an easier way to get the header?
        publicJwk      <- Sync[F].fromOption(
                            header.keyId.flatMap(ds => jwtSet.keyByKeyId(KeyId(ds)).map(_.toPublicJWK.asInstanceOf[RSAJWK])),
                            InvalidCredentials("no matching jwks")
                          )
        publicKey      <- Sync[F].fromEither(publicJwk.toPublicKey.leftMap(e => InvalidCredentials(e.message)))
        jwtClaim       <- Sync[F].fromTry(JwtCirce.decode(token, publicKey))
        _              <- Sync[F].delay(println(s"CFM: audience is $audience"))
        finalClaim     <- maybeClaimMatchingAudience(jwtClaim, audience)
      } yield finalClaim
      Sync[F]
        .attempt(claim)
        .map(_.leftMap(_.getMessage()))
    }
  }

  // TODO: change status based of exception type
  // JwtNotBeforeException(s))
  // JwtExpirationException(e))
  def onFailure[F[_]: Sync]: AuthedRoutes[String, F] =
    Kleisli(_ => OptionT.pure(Response[F](Status.Forbidden)))

  def authMiddleware[F[_]: Sync](
    audience: Option[String],
    jwkProvider: JWKSProvider[F]
  ) =
    AuthMiddleware(authUser(audience, jwkProvider), onFailure)

}
