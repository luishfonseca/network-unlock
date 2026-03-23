{buildGoModule}:
buildGoModule rec {
  pname = "network-unlock";
  version = "0.1.0";
  src = ./.;
  vendorHash = "sha256-bk509AIyOD7vX8sgYsRzWHohaq9CmrdPIDOvV9dNmDk=";

  ldflags = ["-s -w -X main.Version=${version}"];
  env.CGO_ENABLED = 0;

  meta.mainProgram = pname;
}
