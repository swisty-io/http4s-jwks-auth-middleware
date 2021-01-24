val Http4sVersion = "0.21.8"
val CirceVersion = "0.13.0"
val ScalaTestVersion = "3.2.2"

lazy val root = (project in file("."))
  .settings(
    name := "http4s-jwks-auth-middleware",
    organization := "io.swisty",
    version := "0.1",
    scalaVersion := "2.13.3",
    libraryDependencies ++= Seq(
      "org.http4s"    %% "http4s-server"       % Http4sVersion,
      "org.http4s"    %% "http4s-circe"        % Http4sVersion,
      "org.http4s"    %% "http4s-blaze-client" % Http4sVersion,
      "org.http4s"    %% "http4s-testing"      % Http4sVersion    % "test",
      "io.circe"      %% "circe-generic"       % CirceVersion,
      "com.pauldijou" %% "jwt-circe"           % "4.3.0",
      "com.chatwork"  %% "scala-jwk"           % "1.0.5",
      "io.circe"      %% "circe-generic"       % CirceVersion,
      "org.scalatest" %% "scalatest"           % ScalaTestVersion % "test"
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
