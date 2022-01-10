val Http4sVersion = "0.23.7"
val CirceVersion = "0.14.1"
val ScalaTestVersion = "3.2.2"

val replSettings = "import cats._; import cats.implicits._; import cats.data._; import cats.effect._; import cats.effect.unsafe.implicits._".stripMargin

val myReplSettings = Compile / console / initialCommands := replSettings

lazy val root = (project in file("."))
  .settings(myReplSettings)
  .settings(
    name := "http4s-jwks-auth-middleware",
    organization := "io.swisty",
    version := "0.1",
    scalaVersion := "2.13.3",
    libraryDependencies ++= Seq(
      "org.http4s"           %% "http4s-server"                 % Http4sVersion,
      "org.http4s"           %% "http4s-circe"                  % Http4sVersion,
      "org.http4s"           %% "http4s-blaze-client"           % Http4sVersion,
      "org.http4s"           %% "http4s-dsl"                    % Http4sVersion,
      "io.circe"             %% "circe-generic"                 % CirceVersion,
      "com.github.jwt-scala" %% "jwt-circe"                     % "9.0.3",
      "com.chatwork"         %% "scala-jwk"                     % "1.2.22",
      "io.circe"             %% "circe-generic"                 % CirceVersion,
      "org.scalatest"        %% "scalatest"                     % ScalaTestVersion % Test,
      "org.typelevel"        %% "cats-effect-testing-scalatest" % "1.4.0"          % Test
    ),
    addCompilerPlugin("org.typelevel" %% "kind-projector"     % "0.10.3"),
    addCompilerPlugin("com.olegpy"    %% "better-monadic-for" % "0.3.0"),
    addCommandAlias("format", ";scalafmt;test:scalafmt;scalafmtSbt")
  )

scalacOptions ++= Seq(
  "-deprecation",
  "-encoding",
  "UTF-8",
  "-language:higherKinds",
  "-language:postfixOps",
  "-feature",
  "-Xfatal-warnings"
)
