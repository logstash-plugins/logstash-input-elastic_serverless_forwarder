## 2.0.0
  - SSL settings that were marked deprecated in version `0.1.3` are now marked obsolete, and will prevent the plugin from starting.
  - These settings are:
    - `ssl`, which should be replaced by `ssl_enabled`
    - [#11](https://github.com/logstash-plugins/logstash-input-elastic_serverless_forwarder/pull/11)

## 1.0.0
  - Promote from technical preview to GA [#10](https://github.com/logstash-plugins/logstash-input-elastic_serverless_forwarder/pull/10)

## 0.1.5
  - [DOC] Fix attributes to accurately set and clear default codec values [#8](https://github.com/logstash-plugins/logstash-input-elastic_serverless_forwarder/pull/8)

## 0.1.4
  - [DOC] Adds tips for using the logstash-input-elastic_serverless_forwarder plugin with the Elasticsearch output plugin [#7](https://github.com/logstash-plugins/logstash-input-elastic_serverless_forwarder/pull/7)

## 0.1.3
  - Deprecates the `ssl` option in favor of `ssl_enabled` [#6](https://github.com/logstash-plugins/logstash-input-elastic_serverless_forwarder/pull/6)
  - Bumps `logstash-input-http` gem version to `>= 3.7.2` (SSL-normalized)

## 0.1.2
  - [DOC] Adds "Technical Preview" call-out to documentation [#4](https://github.com/logstash-plugins/logstash-input-elastic_serverless_forwarder/pull/4)

## 0.1.1
  - Fixes an issue that prevents this prototype from being instantiated in an actual Logstash pipeline [#3](https://github.com/logstash-plugins/logstash-input-elastic_serverless_forwarder/pull/3)

## 0.1.0
  - Working Prototype: New input to receive events from Elastic Serverless Forwarder (ESF) over HTTP(S) [#1](https://github.com/logstash-plugins/logstash-input-elastic_serverless_forwarder/pull/1)
