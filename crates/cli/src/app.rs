use crate::cli::{Cli, Commands, SigningBackend};
use crate::json::ErrorJson;
use anyhow::Result;
use console::style;

pub fn run(cli: Cli) -> Result<()> {
  let json = cli.json;

  let result = match cli.command {
    Commands::Sign {
      input,
      output,
      backend,
      key,
      embed_uid,
      oidc_issuer,
      fulcio_url,
      rekor_url,
      oidc_client_id,
      oidc_client_secret,
      identity_token,
      digest_algorithm,
    } => match backend {
      SigningBackend::Gpg => {
        let key = key.expect("--key is required for GPG backend");
        crate::sign::sign_gpg(input, output, key, embed_uid, json)
      }
      SigningBackend::Sigstore => crate::sign::sign_sigstore(
        input,
        output,
        oidc_issuer,
        fulcio_url,
        rekor_url,
        oidc_client_id,
        oidc_client_secret,
        identity_token,
        digest_algorithm,
        json,
      ),
    },

    Commands::Verify {
      input,
      cert,
      certificate_identity,
      certificate_identity_regexp,
      certificate_oidc_issuer,
      certificate_oidc_issuer_regexp,
      offline,
    } => crate::commands::verify_pdf(
      input,
      cert,
      certificate_identity,
      certificate_identity_regexp,
      certificate_oidc_issuer,
      certificate_oidc_issuer_regexp,
      offline,
      json,
    ),

    Commands::Challenge {
      input,
      key,
      output,
      embed_uid,
    } => crate::commands::prepare_challenge(input, key, output, embed_uid, json),

    Commands::ApplyResponse {
      input,
      challenge,
      signature,
      output,
    } => crate::commands::apply_response(input, challenge, signature, output, json),
  };

  if let Err(e) = &result {
    if json {
      let causes: Vec<String> = e.chain().skip(1).map(|c| c.to_string()).collect();
      let payload = ErrorJson {
        status: "error",
        error: e.to_string(),
        causes,
      };
      println!("{}", serde_json::to_string(&payload)?);
    } else {
      eprintln!("\n{} {}", style("[ERROR]").red().bold(), style(&e).red());

      for (i, cause) in e.chain().skip(1).enumerate() {
        if i == 0 {
          eprintln!("\n    Caused by:");
        }
        eprintln!("      - {}", style(cause).red());
      }
      eprintln!();
    }
  }

  result
}
