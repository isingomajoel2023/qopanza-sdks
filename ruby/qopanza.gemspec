# frozen_string_literal: true

require_relative "lib/qopanza"

Gem::Specification.new do |spec|
  spec.name = "qopanza"
  spec.version = Qopanza::VERSION
  spec.authors = ["Gsente LLC"]
  spec.summary = "Ruby client for the Qopanza API"
  spec.description = "Post-quantum cryptography (ML-KEM, ML-DSA) and cryptographic discovery from Ruby."
  spec.license = "Apache-2.0"
  spec.required_ruby_version = ">= 3.0"
  spec.homepage = "https://qopanza.com"

  # RubyGems shows these as links on the gem page, and
  # rubygems_mfa_required makes the registry refuse a push from an
  # account without multi-factor auth — a supply-chain control that
  # costs nothing and is embarrassing to omit on a security library.
  spec.metadata = {
    "homepage_uri" => "https://qopanza.com",
    "source_code_uri" => "https://github.com/isingomajoel2023/qopanza-sdks",
    "bug_tracker_uri" => "https://github.com/isingomajoel2023/qopanza-sdks/issues",
    "rubygems_mfa_required" => "true",
  }

  spec.files = Dir["lib/**/*.rb", "README.md", "LICENSE"]
  spec.require_paths = ["lib"]

  # Deliberately no runtime dependencies: net/http, json and base64 are
  # stdlib. A security library that drags in transitive gems is a harder
  # sell to the teams most likely to care about supply chain.
  spec.add_development_dependency "minitest", "~> 5.0"
end
