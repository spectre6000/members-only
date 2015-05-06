class User < ActiveRecord::Base
  before_create {generate_token}
  before_save {email.downcase!}

  validates :name, presence: true, uniqueness: true
  VALID_EMAIL_REGEX = /\A[\w+\-.]+@[a-z\d\-]+(\.[a-z\d\-]+)*\.[a-z]+\z/i
  validates :email, presence: true, format: { with: VALID_EMAIL_REGEX }, uniqueness: true
  validates :password_digest, presence: true
  has_secure_password

  def generate_token
    self.remember_token = encrypted_token
  end

  private
    
    def token
      SecureRandom.urlsafe_base64
    end

    def encrypted_token
      Digest::SHA1.hexdigest(token.to_s)
    end

end
