# encoding: utf-8
require "logstash/inputs/base"
require "logstash/namespace"

require "logstash/plugin_mixins/plugin_factory_support"
require "logstash/plugin_mixins/normalize_config_support"

require 'logstash/inputs/http'
require 'logstash/codecs/json_lines'

class LogStash::Inputs::ElasticServerlessForwarder < LogStash::Inputs::Base
  include LogStash::PluginMixins::PluginFactorySupport
  include LogStash::PluginMixins::NormalizeConfigSupport

  config_name "elastic_serverless_forwarder"

  # bind address
  config :host, :validate => :string, :default => "0.0.0.0"
  config :port, :validate => :number, :required => true

  # optional http basic auth
  config :auth_basic_username,         :validate => :string
  config :auth_basic_password,         :validate => :password

  # ssl-config
  config :ssl,                         :validate => :boolean, :default => true, :deprecated => "Use 'ssl_enabled' instead."
  config :ssl_enabled,                 :validate => :boolean, :default => true

  # ssl-identity
  config :ssl_certificate,             :validate => :path
  config :ssl_key,                     :validate => :path
  config :ssl_key_passphrase,          :validate => :password

  # ssl-trust
  config :ssl_certificate_authorities, :validate => :path, :list => true
  config :ssl_client_authentication,   :validate => %w(none optional required), :default => 'none'
  config :ssl_verification_mode,       :validate => %w(certificate),            :default => 'certificate'

  # ssl-expert-mode
  config :ssl_cipher_suites,           :validate => :string,  :list => true
  config :ssl_supported_protocols,     :validate => :string,  :list => true
  config :ssl_handshake_timeout,       :validate => :number,  :default => 10_000

  def initialize(*a)
    super

    normalize_ssl_configs!

    if original_params.include?('codec')
      fail LogStash::ConfigurationError, 'The `elastic_serverless_forwarder` input does not have an externally-configurable `codec`'
    end

    @internal_http = plugin_factory.input('http').new(inner_http_input_options)
  end

  def register
    logger.debug("registering inner HTTP input plugin")
    @internal_http.register
    logger.debug("registered inner HTTP input plugin")
  end # def register


  def run(queue)
    logger.debug("starting inner HTTP input plugin")
    @internal_http.run(QueueWrapper.new(queue))
    logger.debug('inner HTTP plugin has exited')
  rescue => e
    logger.error("inner HTTP plugin has had an unrecoverable exception: #{e.message} at #{e.backtrace.first}")
    raise
  end

  def stop
    logger.debug("stopping inner HTTP input plugin")
    @internal_http.stop
    logger.debug('inner HTTP plugin has been stopped')
  end

  def close
    logger.debug("closing inner HTTP input plugin")
    @internal_http.close
    logger.debug('inner HTTP plugin has been closed')
  end

  private

  def inner_http_input_options
    @_inner_http_input_options ||= begin
      http_options = {
        # directly-configurable
        'host' => @host,
        'port' => @port,

        # non-configurable codec
        'codec' => plugin_factory.codec('json_lines').new(inner_json_lines_codec_options),
        'additional_codecs' => {},

        # enrichment avoidance
        'ecs_compatibility'            => 'disabled',
        'remote_host_target_field'     => '[@metadata][void]',
        'request_headers_target_field' => '[@metadata][void]',
      }

      if @auth_basic_username
        http_options['user'] = @auth_basic_username
        http_options['password'] = @auth_basic_password || fail(LogStash::ConfigurationError, '`auth_basic_password` is REQUIRED when `auth_basic_username` is provided')
        logger.warn("HTTP Basic Auth over non-secured connection") if @ssl_enabled == false
      end

      if @ssl_enabled == false
        ignored_ssl_settings = @original_params.keys.grep('ssl_')
        logger.warn("Explicit SSL-related settings are ignored because `ssl_enabled => false`: #{ignored_ssl_settings.keys}") if ignored_ssl_settings.any?
      else
        http_options['ssl_enabled'] = true

        http_options['ssl_cipher_suites'] = @ssl_cipher_suites if @original_params.include?('ssl_cipher_suites')
        http_options['ssl_supported_protocols'] = @ssl_supported_protocols if @original_params.include?('ssl_supported_protocols')
        http_options['ssl_handshake_timeout'] = @ssl_handshake_timeout

        http_options.merge!(ssl_identity_options)
        http_options.merge!(ssl_trust_options)
      end

      http_options
    end
  end

  def ssl_identity_options
    ssl_enabled_config = @original_params.include?('ssl') ? 'ssl' : 'ssl_enabled'
    identity_options = {
      'ssl_certificate' => @ssl_certificate || fail(LogStash::ConfigurationError, "`ssl_certificate` is REQUIRED when `#{ssl_enabled_config} => true`"),
      'ssl_key'         => @ssl_key         || fail(LogStash::ConfigurationError, "`ssl_key` is REQUIRED when `#{ssl_enabled_config} => true`")
    }
    identity_options['ssl_key_passphrase'] = @ssl_key_passphrase if @original_params.include?('ssl_key_passphrase')

    identity_options
  end

  def ssl_trust_options
    trust_options = {
      'ssl_client_authentication' => @ssl_client_authentication
    }
    if @ssl_client_authentication == 'none'
      logger.warn("Explicit `ssl_certificate_authorities` is ignored because `ssl_client_authentication => #{@ssl_client_authentication}`")
    else
      trust_options['ssl_certificate_authorities'] = @ssl_certificate_authorities || fail(LogStash::ConfigurationError, "`ssl_certificate_authorities` is REQUIRED when `ssl_client_authentication => #{@ssl_client_authentication}`")
    end

    trust_options
  end

  def inner_json_lines_codec_options
    @_inner_json_lines_codec_options ||= {
      # enrichment avoidance
      'ecs_compatibility' => 'disabled',
    }
  end

  def normalize_ssl_configs!
    @ssl_enabled = normalize_config(:ssl_enabled) do |normalizer|
      normalizer.with_deprecated_alias(:ssl)
    end
  end

  class QueueWrapper
    def initialize(wrapped_queue)
      @wrapped_queue = wrapped_queue
    end

    def << (event)
      event.remove('[@metadata][void]')
      @wrapped_queue << event
    end
  end

end # class LogStash::Inputs::ElasticServerlessForwarder
