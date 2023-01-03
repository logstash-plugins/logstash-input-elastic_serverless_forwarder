require "logstash/devutils/rspec/spec_helper"
require "logstash/devutils/rspec/shared_examples"

require "logstash/inputs/elastic_serverless_forwarder"

require "json"
require "manticore"

describe LogStash::Inputs::ElasticServerlessForwarder do

  let(:generated_certs_directory) { Pathname.new('../fixtures/certs/generated').expand_path(__dir__).realpath }

  let(:client) { Manticore::Client.new(client_options) }
  let(:client_options) { { } }
  let(:request_options) do
    { headers: {"Content-Type" => "application/x-ndjson"} }
  end

  let(:port) { rand(1025...5000) }
  let(:host) { "127.0.0.1" }
  let(:scheme) { 'https' }
  let(:url) { "#{scheme}://#{host}:#{port}" }

  let(:config) { { "host" => host, "port" => port } }

  subject(:esf_input) { described_class.new(config) }

  let!(:queue) { Queue.new }

  context 'baseline' do
    let(:config) { super().merge('ssl' => false) }
    let(:scheme) { 'http' }

    it_behaves_like "an interruptible input plugin" do
      let(:config) { { "port" => port, "ssl" => false } }
    end

    after :each do
      client.clear_pending
      client.close
      esf_input.stop
    end


  end

  context 'no user-defined codec' do
    let(:config) { super().merge('ssl' => false) } # minimal config

    ##
    # @codec ivar is required PENDING https://github.com/elastic/logstash/issues/14828
    context 'codec handling' do
      it 'has an `@codec` ivar that inherits from `LogStash::Codecs::Base`' do
        expect(esf_input).to be_instance_variable_defined(:@codec)
        codec = esf_input.instance_variable_get(:@codec)

        expect(codec).to_not be_nil
        expect(codec.class).to be < LogStash::Codecs::Base # LogStash::Codecs::Delegator shenanigans
      end
    end

    context 'when instantiated with a string codec' do
      let(:config) { super().merge("codec" => "json_lines") }
      it 'fails with a helpful configuration error' do
        expect { described_class.new(config) }.to raise_exception(LogStash::ConfigurationError, a_string_including("codec"))
      end
    end

    context 'when instantiated with a codec instance' do
      let(:codec_instance) { Class.new(LogStash::Codecs::Base) { config_name 'test'}.new("id" => "123") }
      let(:config) { super().merge("codec" => codec_instance) }
      it 'fails with a helpful configuration error' do
        expect { described_class.new(config) }.to raise_exception(LogStash::ConfigurationError, a_string_including("codec"))
      end
    end
  end

  shared_context "basic request handling" do
    let!(:registered_esf_input) { esf_input.tap(&:register) }
    let!(:running_input_thread) { Thread.new { registered_esf_input.run(queue) } }
    before(:each) { wait_until_listening(host, port) }

    after(:each) do
      client.clear_pending
      client.close
      esf_input.stop
      running_input_thread.join(10) || fail('o no')
    end

    let(:ndjson_encoded_body) do
      <<~EONDJSONBODY
        {"hello":"world"}
        {"this":"works"}
        {"message":"and doesn't destroy event.original that was included in payload", "event":{"original":"yes"}}
      EONDJSONBODY
    end

    def wait_until_listening(host, port, timeout=10)
      deadline = Time.now + timeout
      begin
        TCPSocket.new(host, port).close
      rescue Errno::ECONNREFUSED
        raise if Time.now > deadline
        sleep 1
        retry
      end
    end

    def pop_with_timeout(queue, timeout)
      t = Thread.new { queue.pop }
      t.join(timeout) || t.kill
      t.value
    end
  end

  shared_examples 'successful request handling' do
    include_context 'basic request handling'
    describe 'basic receipt of events' do
      it 'puts decoded, unenriched events into the queue' do
        client.post("#{scheme}://#{host}:#{port}/events", request_options.merge(body: ndjson_encoded_body)).call

        event = pop_with_timeout(queue, 30) || fail('nothing written to queue')
        expect(event.get("hello")).to eq('world')

        # ensure enrichment is avoided
        expect(event).to_not include('[event][original]')
        expect(event).to_not include('[@metadata][void]')
        expect(event).to_not include('[host]')

        # ensure additional events are added
        event2 = pop_with_timeout(queue, 1) || fail('only single event written to queue')
        expect(event2.get("this")).to eq('works')

        # ensure an event that _has_ an event.original in the payload is not lost
        event3 = pop_with_timeout(queue, 1) || fail('no third element in the queue')
        expect(event3).to include('[event][original]')
        expect(event3.get('[event][original]')).to eq('yes')
      end
    end
  end

  shared_examples 'bad certificate request handling' do
    include_context 'basic request handling'
    describe 'connection' do
      it 'rejects the connection with a bad_certificate error' do
        expect do
          client.post("#{scheme}://#{host}:#{port}/events", request_options.merge(body: ndjson_encoded_body)).call
        end.to raise_exception(Manticore::ClientProtocolException, a_string_including('bad_certificate'))
      end
    end
  end

  shared_examples 'bad basic auth request handling' do
    include_context 'basic request handling'
    describe 'request' do
      it 'rejects the request with an HTTP 401 Unauthorized' do
        response = client.post("#{scheme}://#{host}:#{port}/events", request_options.merge(body: ndjson_encoded_body)).call
        expect(response).to have_attributes(code: 401, message: 'Unauthorized')
      end
    end
  end

  shared_examples 'basic auth support' do
    context 'when http basic auth is enabled' do
      let(:username) { 'john.doe' }
      let(:password) { 'sUp3r$ecr3t' }
      let(:config) do
        super().merge('auth_basic_username' => username, 'auth_basic_password' => password)
      end

      context 'with valid credentials' do
        let(:request_options) { super().merge(auth: {user: username, password: password}) }

        include_examples 'successful request handling'
      end
      context 'with invalid credentials' do
        let(:request_options) { super().merge(auth: {user: username, password: "incorrect"}) }

        include_examples 'bad basic auth request handling'
      end
      context 'without credentials' do
        include_examples 'bad basic auth request handling'
      end
    end
  end

  describe 'unsecured HTTP' do
    let(:config) { super().merge('ssl' => false) }
    let(:scheme) { 'http' }

    include_examples 'successful request handling'
    include_examples 'basic auth support'
  end

  describe 'SSL enabled' do
    let(:config) do
      super().merge({
        'ssl_certificate' => generated_certs_directory.join('server_from_root.crt').to_path,
        'ssl_key'         => generated_certs_directory.join('server_from_root.key.pkcs8').to_path,
      })
    end
    let(:client_ssl_options) do
      { ca_file: generated_certs_directory.join('root.crt').to_path }
    end
    let(:client_options) do
      super().merge(
        ssl: client_ssl_options
      )
    end

    include_examples 'successful request handling'
    include_examples 'basic auth support'

    context 'ssl_client_authentication => optional' do
      let(:config) do
        super().merge({
          "ssl_client_authentication" => "optional",
          "ssl_certificate_authorities" => generated_certs_directory.join('root.crt').to_path,
        })
      end

      context 'when client provides trusted cert' do
        let(:client_ssl_options) do
          super().merge({
                          keystore: generated_certs_directory.join('client_from_root.p12').to_path,
                          keystore_password: '12345678',
                        })
        end
        include_examples 'successful request handling'
        include_examples 'basic auth support'
      end

      context 'when client does not provide cert' do
        include_examples 'successful request handling'
        include_examples 'basic auth support'
      end

      context 'when client provides CA-signed cert without matching subjectAltName entry' do
        let(:client_ssl_options) do
          super().merge({
                          keystore: generated_certs_directory.join('client_no_matching_subject.p12').to_path,
                          keystore_password: '12345678',
                        })
        end

        include_examples 'successful request handling'

        context 'and `ssl_verification_mode => full`', skip: "pending implementation of `ssl_verification_mode => full`" do
          let(:config) do
            super().merge('ssl_verification_mode' => 'full')
          end

          include_examples 'bad certificate request handling'
        end
      end

      context 'when client provides self-signed cert' do
        let(:client_ssl_options) do
          super().merge({
                          keystore: generated_certs_directory.join('client_self_signed.p12').to_path,
                          keystore_password: '12345678',
                        })
        end

        include_examples 'successful request handling'
        include_examples 'basic auth support'
      end
    end

    context 'ssl_client_authentication => required' do
      let(:config) do
        super().merge({
          "ssl_client_authentication" => "required",
          "ssl_certificate_authorities" => generated_certs_directory.join('root.crt').to_path,
        })
      end

      context 'when client provides trusted cert' do
        let(:client_ssl_options) do
          super().merge({
            keystore: generated_certs_directory.join('client_from_root.p12').to_path,
            keystore_password: '12345678',
          })
        end
        include_examples 'successful request handling'
        include_examples 'basic auth support'
      end

      context 'when client does not provide cert' do
        include_examples 'bad certificate request handling'
      end

      context 'when client provides CA-signed cert without matching subjectAltName entry' do
        let(:client_ssl_options) do
          super().merge({
                          keystore: generated_certs_directory.join('client_no_matching_subject.p12').to_path,
                          keystore_password: '12345678',
                        })
        end

        include_examples 'successful request handling'

        context 'and `ssl_verification_mode => full`', skip: "pending implementation of `ssl_verification_mode => full`" do
          let(:config) do
            super().merge('ssl_verification_mode' => 'full')
          end

          include_examples 'bad certificate request handling'
        end
      end

      context 'when client provides self-signed cert' do
        let(:client_ssl_options) do
          super().merge({
                          keystore: generated_certs_directory.join('client_self_signed.p12').to_path,
                          keystore_password: '12345678',
                        })
        end

        include_examples 'bad certificate request handling'
      end
    end
  end
end
