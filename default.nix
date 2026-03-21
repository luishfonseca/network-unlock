{buildGoModule}:
buildGoModule rec {
  pname = "network-unlock";
  version = "0.1.0";
  src = ./.;
  vendorHash = "sha256-lMELol//HudCZk0BdKdfsbJ1y2r6dWMxfYfnskKdJMo=";

  ldflags = ["-s -w -X main.Version=${version}"];
  env.CGO_ENABLED = 0;

  meta.mainProgramz = pname;
}
