package io.swisty.middleware

import org.http4s.headers._
import org.http4s.Method.POST
import org.http4s._
import org.http4s.client.Client
import io.circe.generic.auto._
import org.http4s.circe._
import cats.effect.{Async, Ref, Resource}
import cats.syntax.all._
import java.time.Instant

//* See the following for a protocol summary
// https://www.oauth.com/oauth2-servers/access-tokens/client-credentials/
// TODO:
// 1) use time acquisition instead of non-standard created_at
// 2) Account for clock drift
// 3) Allow for optional audience parameter

final case class ClientCredentialsConfig(
  tokenUri: Uri,
  clientId: String,
  clientSecret: String,
  scopes: List[String] = List()
)

object ClientCredentialsMiddleware {

  final private case class AuthToken(access_token: String, expires_in: Long, created_at: Long) {
    def expiresAt: Instant = Instant.ofEpochSecond(created_at + expires_in)
  }

  def apply[F[_]](config: ClientCredentialsConfig)(client: Client[F])(implicit F: Async[F]): Client[F] = {

    val form = UrlForm(
      "grant_type" -> "client_credentials",
      "client_id" -> config.clientId,
      "client_secret" -> config.clientSecret,
      "scope" -> config.scopes.mkString(" ")
    )

    val tokenRequest = Request[F](uri = config.tokenUri).withEntity(form).withMethod(POST)

    val tokenRef = Ref.unsafe[F, Option[AuthToken]](None)

    implicit val authResponseDecoder = jsonOf[F, AuthToken]

    def tokenResponse(): F[Option[AuthToken]] =
      client.expect[AuthToken](tokenRequest).flatMap { token => tokenRef.updateAndGet(_ => Some(token)) }

    def getToken(currentInstant: Instant): F[Option[AuthToken]] =
      tokenRef.get.flatMap { token =>
        if (token.isDefined && currentInstant.isBefore(token.get.expiresAt)) tokenRef.get else tokenResponse()
      }

    Client { req =>
      {
        val authTokenF: F[AuthToken] = for {
          now         <- F.realTimeInstant
          tokenOption <- getToken(now)
          token       <- F.fromOption(tokenOption, new Exception("Unable to acquire token"))
        } yield token

        Resource
          .eval(authTokenF)
          .flatMap(token =>
            client.run(req.withHeaders(Authorization(Credentials.Token(AuthScheme.Bearer, token.access_token))))
          )
      }
    }
  }
}
