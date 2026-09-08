# frozen_string_literal: true

require "base64"
require "json"
require "net/http"
require "uri"

# Ruby client for the Qopanza API.
#
# Covers the crypto endpoints (keys, encrypt, decrypt, sign, verify), the
# AI analysis endpoint, and the scanner/posture endpoints that make the API
# useful from CI. Account signup, billing and support are dashboard
# concerns and are not part of this SDK — the same scoping the Python, Go,
# Rust, PHP, TypeScript and Java SDKs use.
#
#   client = Qopanza::Client.new(base_url: "http://localhost:8000", api_key: key)
#
#   # One-line encryption: no key management at all.
#   sealed = client.encrypt(plaintext: "customer sensitive information")
#   client.decrypt(sealed) # => "customer sensitive information"
#
# Byte handling is raw strings at the API boundary with base64 applied
# internally: base64 is a wire-format detail, and making callers encode it
# themselves is how a plaintext ends up double-encoded in production.
#
# Deliberately stdlib-only (net/http, json, base64). A security library
# that drags in a tree of transitive gems is a harder sell to exactly the
# teams most likely to care about supply chain.
#
# This client holds a secret API key, so it belongs server-side.
module Qopanza
  VERSION = "0.1.0"
  DEFAULT_BASE_URL = "http://localhost:8000"

  # Raised for any non-2xx response, or a transport failure.
  #
  # +status_code+ is kept separate from the message so callers can branch
  # on it — a 409 from a revoked key needs different handling from a 429
  # from a rate limit. A status of 0 means the request never reached the
  # API at all.
  class ApiError < StandardError
    attr_reader :status_code, :detail

    def initialize(status_code, detail)
      @status_code = status_code
      @detail = detail
      super("qopanza: [#{status_code}] #{detail}")
    end
  end

  class Client
    # @param transport [#call] optional override with the signature
    #   call(method, uri, body, headers) -> [status, body]. Exists so the
    #   test suite can exercise request encoding and response decoding
    #   without a network, which is where a client library actually breaks.
    def initialize(base_url: DEFAULT_BASE_URL, api_key: nil, timeout: 15, transport: nil)
      base_url = DEFAULT_BASE_URL if base_url.nil? || base_url.empty?
      @base_url = base_url.sub(%r{/+\z}, "")
      @api_key = api_key
      @timeout = timeout
      @transport = transport
    end

    # ---- Keys ---------------------------------------------------------------

    # Generate a keypair. +purpose+ is "kem", "signature", or "hybrid_kem".
    def create_key(purpose:, label: nil)
      body = { purpose: purpose }
      body[:label] = label if label
      request(:post, "/keys", body)
    end

    def get_key(key_id)
      request(:get, "/keys/#{escape(key_id)}")
    end

    # ---- Encrypt / decrypt --------------------------------------------------

    # Seal +plaintext+.
    #
    # Omit +key_id+ for the one-line path, where the platform provisions
    # and reuses a managed key for the account and reports which one it
    # used in "used_managed_key".
    def encrypt(plaintext:, key_id: nil)
      body = { plaintext: Base64.strict_encode64(plaintext) }
      body[:key_id] = key_id if key_id
      request(:post, "/encrypt", body)
    end

    # Open what #encrypt sealed. Pass the hash it returned straight back.
    def decrypt(sealed)
      result = request(:post, "/decrypt", {
        key_id: sealed["key_id"] || sealed[:key_id],
        ciphertext_kem: sealed["ciphertext_kem"] || sealed[:ciphertext_kem],
        ciphertext_payload: sealed["ciphertext_payload"] || sealed[:ciphertext_payload],
        nonce: sealed["nonce"] || sealed[:nonce]
      })
      Base64.strict_decode64(result["plaintext"])
    end

    # ---- Sign / verify ------------------------------------------------------

    def sign(key_id:, message:)
      request(:post, "/sign", { key_id: key_id, message: Base64.strict_encode64(message) })
    end

    # Check a signature.
    #
    # Returns false only when the signature genuinely did not verify. A
    # failed call raises instead — treating an unreachable API as "invalid
    # signature" is how a verification step silently becomes a no-op.
    def verify(key_id:, message:, signature:)
      result = request(:post, "/verify", {
        key_id: key_id,
        message: Base64.strict_encode64(message),
        signature: signature
      })
      result["valid"]
    end

    # ---- AI analysis --------------------------------------------------------

    def analyze(context)
      request(:post, "/analyze", { context: context })
    end

    # ---- Scanner ------------------------------------------------------------

    # Scan submitted source or manifest text. Nothing is fetched — only
    # what you pass is scanned.
    #
    # The returned run has a nil "risk_score" when it failed, rather than
    # zero: a scan that could not run must never read as a clean result.
    def scan_code(filename:, content:)
      request(:post, "/scan/code", { filename: filename, content: content })
    end

    # Probe a live TLS endpoint and record what it actually negotiates,
    # including its certificate's key algorithm.
    def scan_tls(host:, port: 443)
      request(:post, "/scan/tls", { host: host, port: port.zero? ? 443 : port })
    end

    def scan_assets(scan_id)
      request(:get, "/scans/#{escape(scan_id)}/assets")
    end

    # ---- Posture / inventory ------------------------------------------------

    # The account's quantum risk score and what drives it.
    #
    # "score" runs 0-100 where higher is better, so it moves opposite to
    # "quantum_risk". A score of 100 with a nil "last_scan_at" means "no
    # vulnerable cryptography found" on an empty inventory — an absence of
    # evidence, not evidence of safety.
    def security_posture
      request(:get, "/security/posture")
    end

    def crypto_inventory
      request(:get, "/inventory")
    end

    private

    def escape(value)
      URI.encode_www_form_component(value.to_s).gsub("+", "%20")
    end

    def request(method, path, body = nil)
      uri = URI.parse("#{@base_url}/v1#{path}")
      headers = { "Content-Type" => "application/json" }
      headers["X-API-Key"] = @api_key if @api_key

      encoded = body.nil? ? nil : JSON.generate(body)
      status, response_body =
        if @transport
          @transport.call(method, uri, encoded, headers)
        else
          send_request(method, uri, encoded, headers)
        end

      raise ApiError.new(status, extract_detail(response_body)) if status >= 400
      return {} if response_body.nil? || response_body.empty?

      JSON.parse(response_body)
    rescue JSON::ParserError => e
      raise ApiError.new(status || 0, "Response was not valid JSON: #{e.message}")
    end

    # The API returns {"detail": "..."} for its own errors. Anything else —
    # a proxy's HTML error page, say — is surfaced raw rather than
    # swallowed, because "unknown error" helps nobody debug.
    def extract_detail(response_body)
      return "" if response_body.nil?

      parsed = begin
        JSON.parse(response_body)
      rescue JSON::ParserError
        nil
      end

      if parsed.is_a?(Hash) && parsed.key?("detail")
        detail = parsed["detail"]
        return detail.is_a?(String) ? detail : JSON.generate(detail)
      end
      response_body.strip
    end

    def send_request(method, uri, body, headers)
      http = Net::HTTP.new(uri.host, uri.port)
      http.use_ssl = uri.scheme == "https"
      http.open_timeout = @timeout
      http.read_timeout = @timeout

      request_class = {
        get: Net::HTTP::Get,
        post: Net::HTTP::Post,
        put: Net::HTTP::Put,
        delete: Net::HTTP::Delete
      }.fetch(method)

      req = request_class.new(uri.request_uri)
      headers.each { |name, value| req[name] = value }
      req.body = body if body

      response = http.request(req)
      [response.code.to_i, response.body]
    rescue StandardError => e
      raise ApiError.new(0, "Transport error: #{e.message}")
    end
  end
end
