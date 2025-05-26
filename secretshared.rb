class Secretshared < Formula
    desc "Cli para compartir secretos con todo el equipo devs"
    homepage "https://github.com/evaldovega/secretshared"
    url "https://github.com/evaldovega/secretshared/releases/download/productive/secretshared"
    sha256 "528859dd974e6ff8b0b38a3d04bcc5c76d50dbdb831cc7ec28f580d5b952a3f6 "  # Usa `shasum -a 256 archivo.tar.gz` para obtenerlo
    version "0.1.0"
  
    def install
      bin.install "secretshared"
    end
  end