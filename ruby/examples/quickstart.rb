# frozen_string_literal: true

# Quickstart for the Ruby SDK: one-line encryption, signing, and a scan.
#
#   QOPANZA_API_KEY=qsk_... ruby examples/quickstart.rb

require_relative "../lib/qopanza"

api_key = ENV["QOPANZA_API_KEY"]
if api_key.nil? || api_key.empty?
  warn "set QOPANZA_API_KEY (sign up at POST /v1/accounts; the key is shown once)"
  exit 1
end

client = Qopanza::Client.new(
  base_url: ENV.fetch("QOPANZA_BASE_URL", Qopanza::DEFAULT_BASE_URL),
  api_key: api_key
)

# One-line encryption: the platform provisions and reuses a managed key,
# so there is no key management to do at all.
sealed = client.encrypt(plaintext: "customer sensitive information")
opened = client.decrypt(sealed)
puts "round trip: #{opened.inspect} (managed key: #{sealed['used_managed_key']})"

# Signatures with an explicit key.
sig_key = client.create_key(purpose: "signature", label: "orders")
signed = client.sign(key_id: sig_key["id"], message: "order-42-confirmed")
valid = client.verify(key_id: sig_key["id"], message: "order-42-confirmed", signature: signed["signature"])
puts "signature valid: #{valid} (#{sig_key['algorithm']})"

# Discover what cryptography a file uses.
run = client.scan_code(filename: "payments.py", content: "cipher = RSA.generate(2048)\nh = hashlib.md5(x)")
puts "scan: #{run['assets_found']} asset(s), #{run['quantum_vulnerable']} quantum-vulnerable"

posture = client.security_posture
puts "posture: #{posture['score']}/100 (#{posture['quantum_risk']} risk)"
posture["recommended_actions"].each { |action| puts "  - #{action}" }
