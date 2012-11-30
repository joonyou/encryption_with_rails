class EncryptsController < ApplicationController
  def show
    key = "a0e12d601e10154fe5743fd6d2ba3749" # Digest::SHA2.hexdigest("my key")[0..31]
    iv = "15485aefa2f6ef6cf669d040fe60d3f6e55a948848cc7f11feb857f845daf9a0" # Digest::SHA2.hexdigest("my initialization vector")

    secret = Base64.decode64(params[:psst].gsub(" ","+") + "==\n")
    cipher = OpenSSL::Cipher::AES.new(256, :CBC)
    cipher.decrypt
    cipher.key = key
    cipher.iv = iv
    secret_content = cipher.update(secret) + cipher.final

    Rails.logger.debug("secret content passed: #{params[:psst]}")
    render text: secret_content, layout: false
  end
end
