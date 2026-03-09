# frozen_string_literal: true

require "securerandom"
require "tmpdir"
require_relative "../lib/secrets_saver"

Dir.mktmpdir("secrets-saver-ruby-") do |dir|
  file = File.join(dir, "secrets.ep")

  master = ENV["SS_MASTER_KEY"]
  if master.nil? || master.empty?
    print "Enter test master key: "
    master = if $stdin.tty?
               $stdin.noecho(&:gets).to_s.strip.tap { puts }
             else
               $stdin.gets.to_s.strip
             end
  end

  wrong = "#{master}-wrong"

  writer = SecretsSaver::SecretsSaver.new_file(file, prompt: ->(_location) { master })
  writer.set_secret("a", "1")
  writer.set_secret("b", "2")

  raise "Expected value 1 for key a" unless writer.get_secret("a") == "1"
  raise "Unexpected key list" unless writer.list_secrets == ["a", "b"]

  writer.clear_database
  raise "Expected empty key list after clear" unless writer.list_secrets.empty?

  writer.set_secret("x", "y")

  reader = SecretsSaver::SecretsSaver.new_file(file, prompt: ->(_location) { wrong })
  begin
    reader.get_secret("x")
    raise "Expected InvalidKeyOrCorruptedDataError"
  rescue SecretsSaver::InvalidKeyOrCorruptedDataError
    # expected
  end

  puts "ruby_secrets_saver tests passed"
end
